"""
Backend da Newmed - Propostas de Venda
========================================
Uma API bem simples feita em Flask, que guarda tudo num banco SQLite
(um arquivo só, chamado newmed.db, criado automaticamente na primeira vez
que você rodar este arquivo).

Como rodar:
    1) pip install flask
    2) python app.py
    3) o servidor sobe em http://localhost:5000

O app.html (front-end) vai fazer pedidos pra esse endereço.
"""

import json
import secrets
import sqlite3
import time
from functools import wraps

import requests
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

# As credenciais do Omie ficam num arquivo separado (omie_config.py) que
# nunca é enviado pro GitHub. Se esse arquivo ainda não existir ou estiver
# vazio, a sincronização com o Omie simplesmente fica desativada (sem
# quebrar o resto do servidor).
try:
    from omie_config import OMIE_APP_KEY, OMIE_APP_SECRET
except ImportError:
    OMIE_APP_KEY = ""
    OMIE_APP_SECRET = ""

DB_PATH = "newmed.db"

app = Flask(__name__)


# ------------------------------------------------------------------
# CONEXÃO COM O BANCO DE DADOS
# ------------------------------------------------------------------
def get_db():
    """Devolve uma conexão com o banco, reaproveitando a mesma durante
    o mesmo pedido (padrão recomendado pelo próprio Flask)."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row  # permite acessar colunas pelo nome
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    """Cria as tabelas se elas ainda não existirem. Roda uma vez quando
    o servidor liga."""
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id        TEXT PRIMARY KEY,
            nome      TEXT UNIQUE,
            pin_hash  TEXT,
            criado_em TEXT
        );

        CREATE TABLE IF NOT EXISTS sessoes (
            token      TEXT PRIMARY KEY,
            usuario_id TEXT,
            criado_em  TEXT
        );

        CREATE TABLE IF NOT EXISTS clientes (
            cnpj      TEXT PRIMARY KEY,
            razao     TEXT,
            fantasia  TEXT,
            ac        TEXT,
            endereco  TEXT,
            bairro    TEXT,
            cidade    TEXT
        );

        CREATE TABLE IF NOT EXISTS produtos (
            id         TEXT PRIMARY KEY,
            nome       TEXT,
            marca      TEXT,
            valor_unit REAL,
            foto       TEXT,
            estoque    INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS propostas (
            id            TEXT PRIMARY KEY,
            numero        TEXT,
            data          TEXT,
            status        TEXT,
            valor_total   REAL,
            dados_json    TEXT,
            criado_em     TEXT,
            atualizado_em TEXT,
            criado_por    TEXT,
            atualizado_por TEXT
        );
        """
    )
    db.commit()

    # migração: se o banco já existia de antes (sem a coluna "estoque"), adiciona ela agora
    try:
        db.execute("ALTER TABLE produtos ADD COLUMN estoque INTEGER DEFAULT 0")
        db.commit()
    except sqlite3.OperationalError:
        pass  # a coluna já existe, não precisa fazer nada

    db.close()


# ------------------------------------------------------------------
# CORS "na mão" (sem precisar instalar a biblioteca flask-cors)
# Isso é o que permite que o app.html, aberto direto no navegador,
# consiga chamar essa API mesmo estando em "origens" diferentes.
# ------------------------------------------------------------------
@app.after_request
def liberar_cors(resposta):
    resposta.headers["Access-Control-Allow-Origin"] = "*"
    resposta.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resposta.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resposta


@app.route("/api/<path:qualquer>", methods=["OPTIONS"])
def responder_preflight(qualquer):
    # o navegador manda um pedido "OPTIONS" antes do de verdade, só
    # perguntando se pode. Aqui a gente sempre responde que pode.
    return "", 204


def agora():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# ------------------------------------------------------------------
# AUTENTICAÇÃO
# ------------------------------------------------------------------
def usuario_pelo_token(token):
    """Procura na tabela de sessões quem é o dono desse token."""
    if not token:
        return None
    db = get_db()
    linha = db.execute(
        """
        SELECT usuarios.id, usuarios.nome
        FROM sessoes
        JOIN usuarios ON usuarios.id = sessoes.usuario_id
        WHERE sessoes.token = ?
        """,
        (token,),
    ).fetchone()
    return dict(linha) if linha else None


def pegar_token_do_pedido():
    """O front-end manda o token assim: Authorization: Bearer <token>"""
    cabecalho = request.headers.get("Authorization", "")
    if cabecalho.startswith("Bearer "):
        return cabecalho[len("Bearer "):]
    return None


def exigir_login(funcao_da_rota):
    """Decorador: coloca em cima de uma rota pra exigir que a pessoa
    esteja logada. Se não estiver, devolve erro 401 (não autorizado)."""
    @wraps(funcao_da_rota)
    def rota_protegida(*args, **kwargs):
        usuario = usuario_pelo_token(pegar_token_do_pedido())
        if not usuario:
            return jsonify({"erro": "É preciso estar logado."}), 401
        g.usuario_logado = usuario
        return funcao_da_rota(*args, **kwargs)
    return rota_protegida


def criar_sessao(usuario_id):
    """Cria um token novo de sessão pra esse usuário e devolve ele."""
    token = secrets.token_hex(24)
    db = get_db()
    db.execute(
        "INSERT INTO sessoes (token, usuario_id, criado_em) VALUES (?,?,?)",
        (token, usuario_id, agora()),
    )
    db.commit()
    return token


@app.route("/api/usuarios", methods=["GET"])
def listar_usuarios():
    """Lista pública (sem precisar estar logado) só com os nomes —
    usada pra montar a telinha 'Quem é você?' antes do login."""
    db = get_db()
    linhas = db.execute("SELECT id, nome FROM usuarios ORDER BY nome").fetchall()
    return jsonify([dict(linha) for linha in linhas])


@app.route("/api/usuarios", methods=["POST"])
def criar_usuario():
    """Cria uma pessoa nova (nome + PIN de 4 dígitos) e já loga ela."""
    d = request.get_json()
    nome = (d.get("nome") or "").strip()
    pin = (d.get("pin") or "").strip()

    if not nome:
        return jsonify({"erro": "Digite seu nome."}), 400
    if not (pin.isdigit() and len(pin) == 4):
        return jsonify({"erro": "O PIN precisa ter exatamente 4 números."}), 400

    db = get_db()
    ja_existe = db.execute("SELECT id FROM usuarios WHERE nome=?", (nome,)).fetchone()
    if ja_existe:
        return jsonify({"erro": "Já existe alguém cadastrado com esse nome. Escolha esse nome na lista e entre com o PIN, ou use um nome um pouco diferente (ex: sobrenome junto)."}), 400

    usuario_id = secrets.token_hex(8)
    db.execute(
        "INSERT INTO usuarios (id, nome, pin_hash, criado_em) VALUES (?,?,?,?)",
        (usuario_id, nome, generate_password_hash(pin), agora()),
    )
    db.commit()

    token = criar_sessao(usuario_id)
    return jsonify({"ok": True, "token": token, "usuario": {"id": usuario_id, "nome": nome}})


@app.route("/api/entrar", methods=["POST"])
def entrar():
    d = request.get_json()
    nome = (d.get("nome") or "").strip()
    pin = (d.get("pin") or "").strip()

    db = get_db()
    usuario = db.execute("SELECT * FROM usuarios WHERE nome=?", (nome,)).fetchone()
    if not usuario or not check_password_hash(usuario["pin_hash"], pin):
        return jsonify({"erro": "PIN incorreto."}), 401

    token = criar_sessao(usuario["id"])
    return jsonify({
        "ok": True,
        "token": token,
        "usuario": {"id": usuario["id"], "nome": usuario["nome"]},
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    token = pegar_token_do_pedido()
    if token:
        db = get_db()
        db.execute("DELETE FROM sessoes WHERE token=?", (token,))
        db.commit()
    return jsonify({"ok": True})


@app.route("/api/eu", methods=["GET"])
def eu():
    usuario = usuario_pelo_token(pegar_token_do_pedido())
    if not usuario:
        return jsonify({"erro": "Não logado."}), 401
    return jsonify(usuario)


# ------------------------------------------------------------------
# CLIENTES
# ------------------------------------------------------------------
@app.route("/api/clientes", methods=["GET"])
@exigir_login
def listar_clientes():
    db = get_db()
    linhas = db.execute("SELECT * FROM clientes").fetchall()
    return jsonify([dict(linha) for linha in linhas])


@app.route("/api/clientes", methods=["POST"])
@exigir_login
def salvar_cliente():
    d = request.get_json()
    db = get_db()
    db.execute(
        """
        INSERT INTO clientes (cnpj, razao, fantasia, ac, endereco, bairro, cidade)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(cnpj) DO UPDATE SET
            razao=excluded.razao, fantasia=excluded.fantasia, ac=excluded.ac,
            endereco=excluded.endereco, bairro=excluded.bairro, cidade=excluded.cidade
        """,
        (
            d["cnpj"], d.get("razao", ""), d.get("fantasia", ""), d.get("ac", ""),
            d.get("endereco", ""), d.get("bairro", ""), d.get("cidade", ""),
        ),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/clientes/<cnpj>", methods=["DELETE"])
@exigir_login
def excluir_cliente(cnpj):
    db = get_db()
    db.execute("DELETE FROM clientes WHERE cnpj=?", (cnpj,))
    db.commit()
    return jsonify({"ok": True})


# ------------------------------------------------------------------
# PRODUTOS
# ------------------------------------------------------------------
@app.route("/api/produtos", methods=["GET"])
@exigir_login
def listar_produtos():
    db = get_db()
    linhas = db.execute("SELECT * FROM produtos").fetchall()
    return jsonify([dict(linha) for linha in linhas])


@app.route("/api/produtos", methods=["POST"])
@exigir_login
def salvar_produto():
    d = request.get_json()
    db = get_db()
    db.execute(
        """
        INSERT INTO produtos (id, nome, marca, valor_unit, foto, estoque)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            nome=excluded.nome, marca=excluded.marca,
            valor_unit=excluded.valor_unit, foto=excluded.foto,
            estoque=excluded.estoque
        """,
        (d["id"], d.get("nome", ""), d.get("marca", ""), d.get("valorUnit", 0),
         d.get("foto", ""), d.get("estoque", 0)),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/produtos/importar", methods=["POST"])
@exigir_login
def importar_produtos():
    """Recebe uma lista de produtos de uma vez (usado pela importação de CSV)."""
    itens = request.get_json()
    db = get_db()
    for d in itens:
        db.execute(
            """
            INSERT INTO produtos (id, nome, marca, valor_unit, foto)
            VALUES (?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                nome=excluded.nome, marca=excluded.marca, valor_unit=excluded.valor_unit
            """,
            (d["id"], d.get("nome", ""), d.get("marca", ""), d.get("valorUnit", 0), d.get("foto", "")),
        )
    db.commit()
    return jsonify({"ok": True, "importados": len(itens)})


@app.route("/api/produtos/<id>", methods=["DELETE"])
@exigir_login
def excluir_produto(id):
    db = get_db()
    db.execute("DELETE FROM produtos WHERE id=?", (id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/produtos/sincronizar-omie", methods=["POST"])
@exigir_login
def sincronizar_estoque_omie():
    """Busca no Omie a lista COMPLETA de produtos. Para cada um:
    - se já existe aqui (mesmo nome), atualiza o estoque e o valor;
    - se não existe, CRIA um produto novo no app.
    Ou seja, isso importa o catálogo inteiro do Omie pra dentro do app."""
    if not OMIE_APP_KEY or not OMIE_APP_SECRET:
        return jsonify({
            "erro": "As credenciais do Omie ainda não foram configuradas. "
                    "Preencha o arquivo omie_config.py com sua App Key e App Secret."
        }), 400

    db = get_db()
    produtos_locais = {
        linha["nome"].strip().lower(): linha["id"]
        for linha in db.execute("SELECT id, nome FROM produtos").fetchall()
    }

    atualizados = 0
    criados = 0
    pagina = 1
    total_paginas = 1  # será corrigido pela primeira resposta do Omie

    while pagina <= total_paginas:
        payload = {
            "call": "ListarProdutos",
            "app_key": OMIE_APP_KEY,
            "app_secret": OMIE_APP_SECRET,
            "param": [{
                "pagina": pagina,
                "registros_por_pagina": 200,
                "apenas_importado_api": "N",
            }],
        }
        try:
            resposta = requests.post(
                "https://app.omie.com.br/api/v1/geral/produtos/",
                json=payload, timeout=60,
            )
            dados = resposta.json()
        except Exception as erro:
            return jsonify({"erro": f"Não consegui falar com o Omie: {erro}"}), 502

        if "faultstring" in dados:
            return jsonify({"erro": f"O Omie respondeu com um erro: {dados['faultstring']}"}), 400

        total_paginas = dados.get("total_de_paginas", 1)
        lista_omie = dados.get("produto_servico_cadastro", [])

        for p in lista_omie:
            nome_omie = (p.get("descricao") or "").strip()
            if not nome_omie:
                continue
            chave = nome_omie.lower()

            marca = p.get("marca") or ""
            valor = p.get("valor_unitario") or 0
            estoque = p.get("quantidade_estoque")
            if estoque is None:
                estoque = p.get("estoque_atual", 0)

            id_local = produtos_locais.get(chave)
            if id_local:
                # já existe no app -> só atualiza estoque e valor
                db.execute(
                    "UPDATE produtos SET valor_unit=?, estoque=? WHERE id=?",
                    (valor, estoque, id_local),
                )
                atualizados += 1
            else:
                # não existe -> cria um produto novo
                novo_id = p.get("codigo") or secrets.token_hex(6)
                db.execute(
                    """
                    INSERT INTO produtos (id, nome, marca, valor_unit, foto, estoque)
                    VALUES (?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        nome=excluded.nome, marca=excluded.marca,
                        valor_unit=excluded.valor_unit, estoque=excluded.estoque
                    """,
                    (str(novo_id), nome_omie, marca, valor, "", estoque),
                )
                produtos_locais[chave] = str(novo_id)
                criados += 1

        pagina += 1

    db.commit()
    return jsonify({"ok": True, "atualizados": atualizados, "criados": criados})


# ------------------------------------------------------------------
# PROPOSTAS
# ------------------------------------------------------------------
@app.route("/api/propostas", methods=["GET"])
@exigir_login
def listar_propostas():
    db = get_db()
    linhas = db.execute("SELECT * FROM propostas").fetchall()
    resultado = []
    for linha in linhas:
        item = dict(linha)
        item["dados"] = json.loads(item.pop("dados_json") or "{}")
        resultado.append(item)
    return jsonify(resultado)


@app.route("/api/propostas", methods=["POST"])
@exigir_login
def salvar_proposta():
    d = request.get_json()
    db = get_db()
    existente = db.execute(
        "SELECT criado_em, criado_por FROM propostas WHERE id=?", (d["id"],)
    ).fetchone()
    criado_em = existente["criado_em"] if existente else agora()
    criado_por = existente["criado_por"] if existente else g.usuario_logado["nome"]

    db.execute(
        """
        INSERT INTO propostas (id, numero, data, status, valor_total, dados_json,
                                criado_em, atualizado_em, criado_por, atualizado_por)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            numero=excluded.numero, data=excluded.data, status=excluded.status,
            valor_total=excluded.valor_total, dados_json=excluded.dados_json,
            atualizado_em=excluded.atualizado_em, atualizado_por=excluded.atualizado_por
        """,
        (
            d["id"], d.get("numero", ""), d.get("data", ""), d.get("status", "aberto"),
            d.get("valorTotal", 0), json.dumps(d.get("dados", {}), ensure_ascii=False),
            criado_em, agora(), criado_por, g.usuario_logado["nome"],
        ),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/propostas/<id>", methods=["PUT"])
@exigir_login
def atualizar_status_proposta(id):
    d = request.get_json()
    db = get_db()
    db.execute(
        "UPDATE propostas SET status=?, atualizado_em=? WHERE id=?",
        (d["status"], agora(), id),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/propostas/<id>", methods=["DELETE"])
@exigir_login
def excluir_proposta(id):
    db = get_db()
    db.execute("DELETE FROM propostas WHERE id=?", (id,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/status", methods=["GET"])
def status():
    """Só pra testar rapidinho se o servidor está de pé."""
    return jsonify({"ok": True, "mensagem": "Servidor da Newmed rodando!"})


if __name__ == "__main__":
    init_db()
    print("Banco de dados pronto em:", DB_PATH)
    print("Servidor rodando em http://localhost:5000")
    app.run(debug=True, port=5000)
