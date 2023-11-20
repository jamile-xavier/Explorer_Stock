const { verify } = require("jsonwebtoken");
const AppError = require("../utils/AppError");
const authConfig = require("../configs/auth");

function ensureAuthenticated(request, response, next) {
  const authHeader = request.headers;

  if (!authHeader.cookie) {
    throw new AppError("JWT token não informado", 401);
  }

  //[token= "kjhaksdhaslkdha"] -> splikt vai separar só o token
  const [, token] = authHeader.cookie.split("token=");

  try {
    //recuperar informação
    const { role, sub: user_id } = verify(token, authConfig.jwt.secret);

    //inserir na requisição
    request.user = {
      id: Number(user_id),
      role,
    };

    return next();
  } catch {
    throw new AppError("Invalid JWT token", 401);
  }
}

module.exports = ensureAuthenticated;
