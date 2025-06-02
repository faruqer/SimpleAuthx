exports.up = function (knex) {
  return knex.schema.createTable("clients", (table) => {
    table.uuid("id").primary().defaultTo(knex.fn.uuid());
    table.string("name").notNullable();
    table.string("client_id", 128).notNullable().unique();
    table.string("client_secret_hash").notNullable();
    table.jsonb("redirect_uris").notNullable();
    table.timestamps(true, true);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists("clients");
};
