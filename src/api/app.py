from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src import config
from src.api.deps_auth import (ADMIN, ANALISTA, PRODUTOR_EXPORTADOR, require_role,
                               require_role_por_metodo)
from src.api.routers import (alertas, alertas_preditivos, analista, auditoria, auth,
                             catalogo, clima, config_parametros, dados_mercado,
                             dashboard, frutas, ia, leituras, leituras_rejeitadas, lotes,
                             perfis, previsoes, previsoes_ia, recomendacoes, relatorios,
                             relatorios_gerados, risco, sensor_leituras, sensores,
                             usuarios,pareceres, notificacoes)

# O Administrador passa em TODAS as regras (bypass em deps_auth), então não é listado aqui.
# O Produtor/Exportador é somente leitura: nenhuma regra lhe dá POST/PUT/PATCH/DELETE.

# só Administrador
admin = [Depends(require_role(ADMIN))]

# Analista e Produtor consultam (GET); só o Admin escreve
consulta = [Depends(require_role_por_metodo(
    leitura=(ANALISTA, PRODUTOR_EXPORTADOR), escrita=()))]

# Analista consulta e edita (sem excluir); Produtor só consulta; Admin faz tudo
analista_edita = [Depends(require_role_por_metodo(
    leitura=(ANALISTA, PRODUTOR_EXPORTADOR), escrita=(ANALISTA,), exclusao=()))]

# Só Produtor consulta (Analista fora); Admin faz tudo
so_produtor = [Depends(require_role_por_metodo(
    leitura=(PRODUTOR_EXPORTADOR,), escrita=()))]

app = FastAPI(title="API - Dashboard Climático e Logístico")

@app.get("/", include_in_schema=False)
def raiz():
    return {"status": "ok", "docs": "/docs"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

# público (login, refresh, 2FA) — /auth/me exige token
app.include_router(auth.router)
app.include_router(notificacoes.router)

for r in (perfis, usuarios):
    app.include_router(r.router, dependencies=admin)

for r in (leituras, leituras_rejeitadas, sensor_leituras, dashboard, clima, lotes, frutas,
          risco, previsoes, analista):
    app.include_router(r.router, dependencies=consulta)

for r in (sensores, config_parametros, alertas, alertas_preditivos, catalogo,
          relatorios, relatorios_gerados, pareceres):
    app.include_router(r.router, dependencies=analista_edita)

for r in (auditoria, dados_mercado, ia, recomendacoes, previsoes_ia):
    app.include_router(r.router, dependencies=so_produtor)