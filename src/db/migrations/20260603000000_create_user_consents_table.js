exports.up = function (knex) {
  return knex.schema.createTable("user_consents", (table) => {
    table.uuid("id").primary().defaultTo(knex.fn.uuid());
    table.uuid("user_id").notNullable();
    table.uuid("client_id").notNullable();
    table.jsonb("scopes").notNullable();
    table.timestamp("granted_at").notNullable().defaultTo(knex.fn.now());
    table.timestamps(true, true);

    table
      .foreign("user_id")
      .references("id")
      .inTable("users")
      .onDelete("CASCADE");

    table
      .foreign("client_id")
      .references("id")
      .inTable("clients")
      .onDelete("CASCADE");

    table.unique(["user_id", "client_id"]);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists("user_consents");
};
