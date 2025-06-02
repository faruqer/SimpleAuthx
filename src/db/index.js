const knex = require("knex");
const config = require("../config");
const knexfile = require("./knexfile");

const environment = config.env;
const db = knex(knexfile[environment]);

module.exports = db;
