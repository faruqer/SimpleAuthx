/**
 * Initial migration — creates the users table as a baseline.
 */
exports.up = function (knex) {
  return knex.schema.createTable("users", (table) => {
    table.uuid("id").primary().defaultTo(knex.fn.uuid());
    table.string("email").notNullable().unique();
    table.string("password_hash").notNullable();
    table.string("name");
    table.timestamps(true, true); // created_at, updated_at
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists("users");
};
