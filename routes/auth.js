const express = require('express');
const router = express.Router();
const ctrl = require('../controllers/authController');
const auth = require('../middlewares/auth');

router.post('/signup', ctrl.signup);
router.post('/login', ctrl.login);
router.post('/refresh', ctrl.refresh);
router.post('/forget', ctrl.forgetPassword);
router.post('/reset', ctrl.resetPassword);
router.get('/protected', auth(), ctrl.protectedSample);
router.get('/admin-only', auth('admin'), (req, res) => res.json({ msg: 'Only admin can see this' }));

module.exports = router;
