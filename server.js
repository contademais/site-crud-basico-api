/* Importações */

import express from "express";
import cors from "cors";
import { PrismaClient } from "./generated/prisma/default.js";
import bcryptjs from "bcryptjs";
import jwt from "jsonwebtoken";
import validator from "validator";
import dotenv from "dotenv";

/* Código */

dotenv.config();

const port = process.env.PORT || 3333;

const prisma = new PrismaClient();

const app = express();
app.use(express.json());
app.use(cors());

// Register

app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem-vindo ao back-end!" });
});

app.post("/register", async (req, res) => {
  if (
    req.body.name.trim() == "" ||
    req.body.email.trim() == "" ||
    req.body.password.trim() == ""
  ) {
    return res.status(422).json({ message: "Preencha todos os campos!" });
  }

  if (req.body.password.length < 8) {
    return res
      .status(422)
      .json({ message: "A senha precisa ter pelo menos 8 caracteres!" });
  }

  if (!validator.isEmail(req.body.email)) {
    return res.status(422).json({ message: "E-mail inválido!" });
  }

  const salt = await bcryptjs.genSalt(12);
  const passwordHash = await bcryptjs.hash(req.body.password, salt);

  try {
    await prisma.user.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: passwordHash,
      },
    });
    res.status(201).json({ message: "Usuário cadastrado com sucesso!" });
  } catch (e) {
    res.status(500).json({ message: "Usuário já existe!" });
  }
});

// Login

app.post("/login", async (req, res) => {
  if (!req.body.email.trim() != "" || !req.body.password.trim() != "") {
    res.status(422).json({ message: "Preencha todos os campos!" });
  }

  const user = await prisma.user.findUnique({
    where: {
      email: req.body.email,
    },
  });

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  const isPasswordValid = await bcryptjs.compare(
    req.body.password,
    user.password
  );

  if (!isPasswordValid) {
    return res.status(401).json({ message: "Senha incorreta!" });
  }

  try {
    const secret = process.env.JWT_SECRET;

    const token = jwt.sign(
      {
        id: user.id,
        permLevel: user.permLevel,
      },
      secret
    );
    res.status(200).json({ message: "Usuário logado com sucesso!", token });
  } catch (e) {
    res
      .status(500)
      .json({ message: "Erro no servidor, tente novamente mais tarde!" });
  }
});

app.get("/users/todos", checkToken, async (req, res) => {
  let users = [];

  if (req.query) {
    try {
      users = await prisma.user.findMany({
        where: {
          id: req.query.id,
          name: req.query.name,
          password: req.query.password,
          email: req.query.email,
        },
      });
    } catch (e) {
      res.status(500).json({ error: e.message });
    }
  } else {
    res.status(422).json({ message: "Não encontrado" });
  }

  res.status(200).json(users);
});

app.get("/users/:email", checkToken, async (req, res) => {
  let user = [];
  if (req.query) {
    try {
      user = await prisma.user.findUnique({
        omit: {
          password: true,
        },
        where: {
          email: req.params.email,
        },
      });
      user !== null ? res.status(200).json(user) : print(user.name);
    } catch (e) {
      res.status(404).json({ message: "Usuário não encontrado" });
    }
  } else {
    res.status(422).json({ message: "Não encontrado" });
  }
});

async function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Tenha certeza de estar logado!" });
  }

  try {
    const secret = process.env.JWT_SECRET;
    jwt.verify(token, secret);

    next();
  } catch (e) {
    res.status(400).json({ message: "Tenha certeza de estar logado!" });
  }
}

async function checkIsAdm(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Tenha certeza de estar logado!" });
  }

  try {
    const secret = process.env.JWT_SECRET;
    const user = jwt.decode(token, secret);

    if (user.permLevel >= 3) {
      next();
    } else {
      return res.status(401).json({ message: "Sem permissão suficiente!" });
    }
  } catch (e) {
    res.status(400).json({ message: "Tenha certeza de estar logado!" });
  }
}

app.post("/users/autenticar", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    const secret = process.env.JWT_SECRET;
    jwt.verify(token, secret);

    res.status(200).json({ message: "Usuário autenticado com sucesso!" });
  } catch (e) {
    res.status(500).json({ message: "Não foi possivel autenticar o usuário." });
  }
});

/*
adsonlearn
8w2xaFiEiL2FM6rs
*/

/*put (editar)
app.put("/users/:id", async (req, res) => {
  await prisma.user.update({
    where: {
      id: req.params.id,
    },
    data: {
      email: req.body.email,
      name: req.body.name,
      password: req.body.password,
    },
  });

  res.status(201).json(req.body);
});
*/

app.delete("/users/:id", checkIsAdm, async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  const secret = process.env.JWT_SECRET;

  const user = jwt.decode(token, secret);

  const requiredUser = await prisma.user.findUnique({
    where: {
      id: req.params.id,
    },
  });

  if (user.permLevel <= requiredUser.permLevel) {
    return res.status(401).json({ message: "Sem permissão suficiente!" });
  }

  await prisma.user.delete({
    where: {
      id: req.params.id,
    },
  });

  res.status(204).json({ message: "Usuário deletado com sucesso!" });
});

app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
