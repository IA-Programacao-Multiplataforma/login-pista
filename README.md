# Login (porta 8081)

Cadastro, login e emissão do **JWT**. Spring Boot, Spring Security, MongoDB. Senhas com **BCrypt**. Estrutura em camadas: `domain` (entidades e portas) e `spring` (controllers, repositórios Mongo, segurança).

## Endpoints
Pelo gateway o prefixo é `/login` (por exemplo, `POST /login/autenticacao/v1/login`).

| Método e caminho | O que faz | Acesso |
|---|---|---|
| `POST /autenticacao/v1/create` | Cria a conta (papel `USER`) e devolve o token | público |
| `POST /autenticacao/v1/login` | Entra com `email` e `password` e devolve o token | público |
| `POST /autenticacao/v1/logout` | Limpa o cookie `access_token` | público |
| `GET /autenticacao/v1/me` | Dados do usuário logado (sem a senha) | logado |
| `PUT /usuarios` | Atualiza a **própria** conta (cep e senha) | logado |
| `DELETE /usuarios/{id}` | Apaga a própria conta; o ADMIN apaga qualquer uma | logado |

Cadastro: `{ "username", "email", "password", "cep" }`. O e-mail vira minúsculo e é o login. Username ou e-mail repetidos dão **409**. Quem se cadastra **nunca** recebe `ADMIN` (as roles do corpo são ignoradas).

## JWT
- HS256, validade de **1 hora**, `subject` = e-mail, claim `roles` = `["ROLE_ADMIN","ROLE_USER"]`.
- Vai no header `Authorization: Bearer <token>` (também aceita o cookie `access_token`).
- O segredo vem da variável de ambiente `JWT_SECRET` (mínimo de 32 caracteres; o serviço não sobe sem ele) e precisa ser **o mesmo** do gateway, da fila e do pedido.

## Como virar ADMIN
No Atlas, edite o usuário e acrescente `ADMIN` em `roles`.

## Como rodar
```bash
./mvnw spring-boot:run
```
Antes, defina as variáveis de ambiente (nada de senha no código):

| Variável | Para quê |
|---|---|
| `MONGO_URI` | URI do MongoDB Atlas (banco `pm`) |
| `JWT_SECRET` | segredo do JWT, o mesmo do gateway, da fila e do pedido |

## Testes
```bash
./mvnw test
```
36 testes (JWT, filtro, cadastro, login, conta). Não precisam de banco nem de variáveis: os valores de teste ficam em `src/test/resources/application.properties`.

