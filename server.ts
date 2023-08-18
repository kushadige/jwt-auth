import "./config.js";
import express, { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

const app = express();
app.use(express.json());

function verifyToken(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers["authorization"]!;
    const token = authHeader.split(" ")[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET!, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } catch (err) {
    return res.sendStatus(401);
  }
}

let refreshTokens: Array<string> = [];

app.get("/", verifyToken, (req: Request, res: Response) => {
  res.status(200).json({ message: "Welcome!" });
});

app.post("/token", (req: Request, res: Response) => {
  const refreshToken = req.body.token;
  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(401);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!, (err, user) => {
    if (err) return res.sendStatus(403);
    user = { username: user.username };
    const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, {
      expiresIn: 20,
    });
    res.status(200).json({ accessToken });
  });
});

app.post("/login", (req: Request, res: Response) => {
  const user = { username: req.body.username };
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET!, {
    expiresIn: 20,
  });
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET!);
  refreshTokens.push(refreshToken);
  res.status(200).json({ accessToken, refreshToken });
});

app.listen(3000, () => {
  console.log("Server is running on port 3000.");
});
