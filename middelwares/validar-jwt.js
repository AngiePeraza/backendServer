const jwt = require('jsonwebtoken');
const Usuario = require('../models/usuario');

const validarJWT = (req, res, next) => {

    //Leer el token
    const token = req.header('x-token');
    console.log(token);

    if (!token) {
        res.status(401).json({
            ok: false,
            msg: 'No hay token en la petición'
        });
    }

    try {
        const { uid } = jwt.verify(token, process.env.JWT_SECRET);
        req.uid = uid;

        next();
    } catch (error) {
        return res.status(401).json({
            ok: false,
            msg: 'El token no es correcto'
        });
    }
}

const validarADMIN_ROLE = async (req, res, next) => {
    const uid = req.uid;

    try {
        const usuarioDB = await Usuario.findById(uid);

        if (!usuarioDB) {
            return res.status(404).json({
                ok: false,
                msg: 'No existe el usuario'
            });
        }

        if (usuarioDB.role !== 'ADMIN_ROLE') {
            return res.status(402).json({
                ok: false,
                msg: 'El usuario no es adminsitrador'
            });
        }

        next();

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        })
    }
}

const validarADMIN_ROLE_o_MismoUsuario = async (req, res, next) => {
    const uid = req.uid;
    const id = req.params.id;

    try {
        const usuarioDB = await Usuario.findById(uid);

        if (!usuarioDB) {
            return res.status(404).json({
                ok: false,
                msg: 'No existe el usuario'
            });
        }

        if (usuarioDB.role !== 'ADMIN_ROLE' && uid !== id) {
            return res.status(402).json({
                ok: false,
                msg: 'El usuario no es adminsitrador'
            });
        }

        next();

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        })
    }
}

module.exports = {
    validarJWT,
    validarADMIN_ROLE,
    validarADMIN_ROLE_o_MismoUsuario
}