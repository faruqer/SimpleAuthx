exports.up = function (knex) {
  return knex.schema.createTable("auth_codes", (table) => {
    table.uuid("id").primary().defaultTo(knex.fn.uuid());
    table.string("code", 255).notNullable().unique();
    table.uuid("user_id").notNullable();
    table.uuid("client_id").notNullable();
    table.string("redirect_uri", 2048).notNullable();
    table.jsonb("scopes").notNullable();
    table.timestamp("expires_at").notNullable();
    table.boolean("is_used").notNullable().defaultTo(false);
    table.timestamp("used_at");
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

    table.index(["client_id", "code"]);
    table.index(["expires_at"]);
  });
};

exports.down = function (knex) {
  return knex.schema.dropTableIfExists("auth_codes");
};
