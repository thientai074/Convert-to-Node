import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";
import { User } from "../models/user.model";

dotenv.config({ path: `.env.${process.env.NODE_ENV}` });

let refreshTokens: any = [];

class authController {
  generateAccessToken(user: any) {
    return jwt.sign(
      {
        id: user.id,
        role: user.role,
      },
        'hello',
      { expiresIn: "15m" }
    );
  }

  generateRefreshToken(user: any) {
    return jwt.sign(
      {
        id: user.id,
        role: user.role,
      },
      "hello",
      { expiresIn: "365d" }
    );
  }

  async login(req: Request, res: Response) {
    try {
      const user = await User.findOne({ email: req.body.email });

      if (!user) {
        res.json("Incorrect username");
      }

      const validPassword =
        user && (await bcrypt.compare(req.body.password, user.password));

      if (!validPassword) {
        res.json("Incorrect password");
      }
      if (user && validPassword) {
        //Generate access token
        const accessToken = jwt.sign(
          {
            id: user.id,
            role: user.role,
          },
          "hello"
        );

        const { password, ...others } = user;

        res.json({ accessToken, user });
      }
    } catch (err) {
      res.json(err);
    }
  }

  async requestRefreshToken(req: Request, res: Response) {
    //Take refresh token from user
    const refreshToken = req.cookies.refreshToken;
    //Send error if token is not valid
    if (!refreshToken) return res.status(401).json("You're not authenticated");
    if (!refreshTokens.includes(refreshToken)) {
      return res.json("Refresh token is not valid");
    }
    jwt.verify(refreshToken, "hello", (err: any, user: any) => {
      if (err) {
        console.log(err);
      }
      refreshTokens = refreshTokens.filter(
        (token: any) => token !== refreshToken
      );
      //create new access token, refresh token and send to user
      const newAccessToken = this.generateAccessToken(user);
      const newRefreshToken = this.generateRefreshToken(user);
      refreshTokens.push(newRefreshToken);
      res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: false,
        path: "/",
        sameSite: "strict",
      });
      res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    });
  }
}

export default new authController();
