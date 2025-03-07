import Users from "../models/UserModel.js";
import argon2 from "argon2";
import jwt from "jsonwebtoken";

export const getUsers = async (req, res) => {
    try {
        const users = await Users.findAll({
            attributes: ["id", "name", "email"],
        });
        res.json(users);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Internal Server Error" });
    }
};

export const Register = async (req, res) => {
    const { name, email, password, confPassword } = req.body;

    if (password !== confPassword)
        return res.status(400).json({ msg: "Password and Confirm Password do not match" });

    try {
        const hashPassword = await argon2.hash(password);
        await Users.create({
            name: name,
            email: email,
            password: hashPassword,
        });
        res.json({ msg: "Registered Successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Registration Failed" });
    }
};

export const Login = async (req, res) => {
    try {
        const user = await Users.findOne({
            where: { email: req.body.email },
        });

        if (!user) return res.status(404).json({ msg: "Email Not Found" });

        const match = await argon2.verify(user.password, req.body.password);
        if (!match) return res.status(400).json({ msg: "Wrong Password" });

        const userId = user.id;
        const name = user.name;
        const email = user.email;
        const accessToken = jwt.sign(
            { userId, name, email },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "20s" }
        );
        const refreshToken = jwt.sign(
            { userId, name, email },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "1d" }
        );

        await Users.update(
            { refresh_token: refreshToken },
            { where: { id: userId } }
        );

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        });

        res.json({ accessToken });
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Login Failed" });
    }
};

export const Logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) return res.sendStatus(204);

        const user = await Users.findOne({ where: { refresh_token: refreshToken } });
        if (!user) return res.sendStatus(204);

        await Users.update(
            { refresh_token: null },
            { where: { id: user.id } }
        );

        res.clearCookie("refreshToken");
        return res.sendStatus(200);
    } catch (error) {
        console.error(error);
        res.status(500).json({ msg: "Logout Failed" });
    }
};
