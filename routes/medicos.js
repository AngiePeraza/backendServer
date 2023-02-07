/**
 * Ruta: /api/medicos
 */

const { Router } = require('express');
const { check } = require('express-validator');
const { validarCampos } = require('../middelwares/validar-campos');
const { validarJWT } = require('../middelwares/validar-jwt');

const {
    getMedicos,
    crearMedico,
    actualizarMedico,
    borrarMedico,
    getMedicoById
} = require('../controllers/medicos');

const router = Router();

router.get('/', validarJWT, getMedicos);

router.post('/',
    [
        validarJWT,
        check('nombre', 'El nombre del médico es obligatorio.').not().isEmpty(),
        check('hospital', 'El hospital id debe ser válido.').isMongoId(),
        validarCampos
    ],
    crearMedico
);

router.put('/:id',
    [
        validarJWT,
        check('nombre', 'El nombre del médico es obligatorio.').not().isEmpty(),
        check('hospital', 'El hospital id debe ser válido.').isMongoId(),
        validarCampos
    ],
    actualizarMedico
);

router.delete('/:id',
    validarJWT,
    borrarMedico
);

router.get('/:id',
    validarJWT,
    getMedicoById
);


module.exports = router;