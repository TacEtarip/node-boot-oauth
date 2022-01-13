const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const randomstring = require("randomstring");
const fs = require("fs").promises;
const path = require("path");
class OauthBoot {
  constructor(expressApp, knex, jwtSecret) {
    this.expressApp = expressApp;
    this.knex = knex;
    this.expressSecured = this.bootOauthExpress(expressApp);
    this.jwtSecret = jwtSecret;
  }

  async init() {
    try {
      await this.auditDataBase();
      this.expressSecured.use(this.decodeToken());
      this.expressSecured.use(this.guard());
      this.addEndPoints();
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }

  async auditDataBase() {
    try {
      const tablesExpected = {
        OAUTH2_Subjects: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          name: {
            defaultValue: null,
            type: "varchar",
            maxLength: 45,
            nullable: false,
          },
        },
        OAUTH2_Users: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          subject_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          username: {
            defaultValue: null,
            type: "varchar",
            maxLength: 45,
            nullable: false,
          },
          password: {
            defaultValue: null,
            type: "varchar",
            maxLength: 75,
            nullable: false,
          },
        },
        OAUTH2_Clients: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          subject_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          identifier: {
            defaultValue: null,
            type: "varchar",
            maxLength: 100,
            nullable: false,
          },
          access_token: {
            defaultValue: null,
            type: "varchar",
            maxLength: 255,
            nullable: false,
          },
        },
        OAUTH2_SubjectRole: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          subject_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          roles_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
        },
        OAUTH2_Roles: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          identifier: {
            defaultValue: null,
            type: "varchar",
            maxLength: 100,
            nullable: false,
          },
        },
        OAUTH2_Applications: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          identifier: {
            defaultValue: null,
            type: "varchar",
            maxLength: 100,
            nullable: false,
          },
        },
        OAUTH2_RoleOption: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          options_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          roles_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
        },
        OAUTH2_Options: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          applicationPart_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          allowed: {
            defaultValue: null,
            type: "varchar",
            maxLength: 75,
            nullable: false,
          },
        },
        OAUTH2_ApplicationPart: {
          id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
          partIdentifier: {
            defaultValue: null,
            type: "varchar",
            maxLength: 100,
            nullable: false,
          },
          applications_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
            nullable: false,
          },
        },
      };

      let falseCount = 0;

      for (const tableExpected in tablesExpected) {
        if (Object.hasOwnProperty.call(tablesExpected, tableExpected)) {
          const result = await this.knex.schema.hasTable(tableExpected);
          if (result === false) {
            falseCount++;
            break;
          }
        }
      }

      // TODO: PARAMETRIZE DROP TABLE
      if (falseCount > 0) {
        console.log("Tables will be created from 0");
        await this.createTables();
      } else {
        let reCreate = false;
        for (const tableExpected in tablesExpected) {
          if (Object.hasOwnProperty.call(tablesExpected, tableExpected)) {
            const [inconsistencies, error] = await this.auditTableColumn(
              tableExpected,
              tablesExpected[tableExpected]
            );

            if (error) {
              throw new Error(
                `An error ocurred while auditing table ${tableExpected}`
              );
            }

            if (inconsistencies.length > 0) {
              reCreate = true;
              console.log(`Table ${tableExpected} inconsistencies in columns:`);
              for (const inconsistency of inconsistencies) {
                console.log(inconsistency + "/n");
              }
              console.log("Tables will be created from 0");
            }
          }
        }
        if (reCreate) {
          await this.createTables();
        }
      }
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }

  async createTables() {
    try {
      await this.dropTables();

      await this.knex.schema.createTable("OAUTH2_Applications", (table) => {
        table.increments("id");
        table.string("identifier", 100).notNullable().unique();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_ApplicationPart", (table) => {
        table.increments("id");
        table.string("partIdentifier", 100).notNullable();
        table.integer("applications_id").unsigned().notNullable();
        table.foreign("applications_id").references("OAUTH2_Applications.id");
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Subjects", (table) => {
        table.increments("id");
        table.string("name", 45).notNullable();
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Users", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.string("username", 45).notNullable().unique();
        table.string("password", 75).notNullable();
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Clients", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.string("identifier", 100).notNullable().unique();
        table.string("access_token", 255).notNullable();
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Options", (table) => {
        table.increments("id");
        table.string("allowed", 75).notNullable();
        table.integer("applicationPart_id").unsigned().notNullable();
        table
          .foreign("applicationPart_id")
          .references("OAUTH2_ApplicationPart.id");
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Roles", (table) => {
        table.increments("id");
        table.string("identifier", 100).notNullable().unique();
        table.boolean("deleted").defaultTo(false);
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_SubjectRole", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.integer("roles_id").unsigned().notNullable();
        table.foreign("roles_id").references("OAUTH2_Roles.id");
        table.unique(["subject_id", "roles_id"]);
      });

      await this.knex.schema.createTable("OAUTH2_RoleOption", (table) => {
        table.increments("id");
        table.integer("options_id").unsigned().notNullable();
        table.foreign("options_id").references("OAUTH2_Options.id");
        table.integer("roles_id").unsigned().notNullable();
        table.foreign("roles_id").references("OAUTH2_Roles.id");
        table.unique(["options_id", "roles_id"]);
      });

      await this.knex.transaction(async (trx) => {
        try {
          const applicationId = await trx("OAUTH2_Applications").insert({
            identifier: "OAUTH2_master",
          });

          const applicationPartIds = [];

          const partsToInsert = [
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_global",
            },
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_user",
            },
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_client",
            },
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_application",
            },
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_role",
            },
            {
              applications_id: applicationId[0],
              partIdentifier: "OAUTH2_option",
            },
          ];

          for (const part of partsToInsert) {
            const applicationPartId = await trx(
              "OAUTH2_ApplicationPart"
            ).insert(part);
            applicationPartIds.push(applicationPartId[0]);
          }

          console.log(applicationPartIds);

          const oauthInsert = [
            {
              applicationPart_id: applicationPartIds[0],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[1],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[1],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[1],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[1],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[1],
              allowed: "select",
            },
            {
              applicationPart_id: applicationPartIds[2],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[2],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[2],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[2],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[2],
              allowed: "select",
            },
            {
              applicationPart_id: applicationPartIds[3],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[3],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[3],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[3],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[3],
              allowed: "select",
            },
            {
              applicationPart_id: applicationPartIds[4],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[4],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[4],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[4],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[4],
              allowed: "select",
            },
            {
              applicationPart_id: applicationPartIds[5],
              allowed: "*",
            },
            {
              applicationPart_id: applicationPartIds[5],
              allowed: "create",
            },
            {
              applicationPart_id: applicationPartIds[5],
              allowed: "update",
            },
            {
              applicationPart_id: applicationPartIds[5],
              allowed: "delete",
            },
            {
              applicationPart_id: applicationPartIds[5],
              allowed: "select",
            },
          ];

          const optionId = await trx("OAUTH2_Options").insert(oauthInsert);

          const roleId = await trx("OAUTH2_Roles").insert({
            identifier: "admin",
          });

          await trx("OAUTH2_RoleOption").insert([
            {
              options_id: optionId[0],
              roles_id: roleId[0],
            },
          ]);

          const subjectId = await trx("OAUTH2_Subjects").insert({
            name: "Admin",
          });

          await trx("OAUTH2_SubjectRole").insert({
            subject_id: subjectId[0],
            roles_id: roleId[0],
          });

          const password = randomstring.generate();

          const encryptedPassword = await bcrypt.hash(password, 10);

          const access_token = jwt.sign(
            {
              data: {
                subjectType: "client",
                identifier: "admin",
              },
            },
            this.jwtSecret
          );

          const encryptedAccessToken = await bcrypt.hash(access_token, 10);

          await trx("OAUTH2_Users").insert({
            username: "admin",
            password: encryptedPassword,
            subject_id: subjectId,
          });

          await trx("OAUTH2_Clients").insert({
            identifier: "admin",
            access_token: encryptedAccessToken,
            subject_id: subjectId,
          });

          console.log("Created file credentials.txt in the cwd");

          await fs.writeFile(
            path.join(process.cwd(), "/credentials.txt"),
            `Credentials for the admin user in it.\n
              Username: admin \n   
              Password: ${password}
              Credentials for the admin client in it.\n
              access_token: ${access_token}`
          );
        } catch (error) {
          console.log(error);
          throw new Error(error.message);
        }
      });
    } catch (error) {
      console.log(error);
      throw new Error(error.message);
    }
  }

  async dropTables() {
    try {
      const tablesToDropInOrder = [
        "OAUTH2_Users",
        "OAUTH2_Clients",
        "OAUTH2_SubjectRole",
        "OAUTH2_Subjects",
        "OAUTH2_RoleOption",
        "OAUTH2_Roles",
        "OAUTH2_Options",
        "OAUTH2_ApplicationPart",
        "OAUTH2_Applications",
      ];
      for (const tableName of tablesToDropInOrder) {
        await this.knex.schema.dropTableIfExists(tableName);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }

  async auditTableColumn(tableName, columnsToMatch) {
    try {
      const columns = await this.knex.table(tableName).columnInfo();
      const tableColumnInconsistencies = [];
      for (const column in columnsToMatch) {
        if (!columns[column]) {
          tableColumnInconsistencies.push(`Column ${column} does not exist`);
        } else {
          if (
            JSON.stringify(columns[column]) !==
            JSON.stringify(columnsToMatch[column])
          )
            tableColumnInconsistencies.push(
              `Column ${column} is not compatible`
            );
        }
      }

      return [tableColumnInconsistencies, null];
    } catch (error) {
      console.log(error);
      return [null, message.error];
    }
  }

  bootOauthExpress(expressApp) {
    expressApp.obPost = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.post(path, ...handler);
    };

    expressApp.obGet = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.get(path, ...handler);
    };

    expressApp.obPut = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.put(path, ...handler);
    };

    expressApp.obDelete = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.delete(path, ...handler);
    };

    return expressApp;
  }

  static bootOauthExpressRouter(expressRouter) {
    expressRouter.obPost = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.post(path, ...handler);
    };

    expressRouter.obGet = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.get(path, ...handler);
    };

    expressRouter.put = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.put(path, ...handler);
    };

    expressRouter.obDelete = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.delete(path, ...handler);
    };

    return expressRouter;
  }

  addEndPoints() {
    // Create User
    this.expressSecured.obPost(
      "/auth/user",
      "OAUTH2_user:create",
      this.validateBody({
        username: { type: "string" },
        password: { type: "string" },
        roles: { type: "array" },
        name: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { username, password, name, roles } = req.body;
          const encryptedPassword = await bcrypt.hash(password, 10);

          await this.knex.transaction(async (trx) => {
            try {
              const firstResult = await trx("OAUTH2_Subjects").insert({
                name,
              });
              await trx("OAUTH2_Users").insert({
                username: username.toLowerCase(),
                password: encryptedPassword,
                subject_id: firstResult[0],
              });

              const subjectRolesToInsert = roles.map((r) => {
                return { subject_id: firstResult[0], roles_id: r.id };
              });

              await trx("OAUTH2_SubjectRole").insert(subjectRolesToInsert);
            } catch (error) {
              throw new Error(error.message);
            }
          });

          return res.status(201).json({ code: 200000, message: "User added" });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Create Client
    this.expressSecured.obPost(
      "/auth/client",
      "OAUTH2_client:create",
      this.validateBody({
        identifier: { type: "string" },
        roles: { type: "array" },
        name: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { identifier, name, roles } = req.body;

          const access_token = jwt.sign(
            {
              data: {
                subjectType: "client",
                identifier: identifier,
              },
            },
            this.jwtSecret
          );

          const encryptedAccessToken = await bcrypt.hash(access_token, 10);

          await this.knex.transaction(async (trx) => {
            try {
              const firstResult = await trx("OAUTH2_Subjects").insert({
                name,
              });

              await trx("OAUTH2_Clients").insert({
                identifier: identifier.toLowerCase(),
                access_token: encryptedAccessToken,
                subject_id: firstResult[0],
              });

              const subjectRolesToInsert = roles.map((r) => {
                return { subject_id: firstResult[0], roles_id: r.id };
              });

              await trx("OAUTH2_SubjectRole").insert(subjectRolesToInsert);
            } catch (error) {
              throw new Error(error.message);
            }
          });

          return res.status(201).json({
            code: 200000,
            message: "Client added",
            content: { access_token },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Create Role
    this.expressSecured.obPost(
      "/auth/role",
      "OAUTH2_role:create",
      this.validateBody({
        identifier: { type: "string" },
        allowedObject: { type: "object" },
      }),
      async (req, res) => {
        try {
          const { identifier, allowedObject } = req.body;
          await this.knex.transaction(async (trx) => {
            try {
              const insertResult = await trx("OAUTH2_Roles").insert({
                identifier: identifier.toLowerCase(),
              });
              const insertRoleOptions = [];
              for (const allowed in allowedObject) {
                for (const a of allowedObject[allowed]) {
                  insertRoleOptions.push({
                    roles_id: insertResult[0],
                    options_id: a.id,
                  });
                }
              }
              console.log(insertRoleOptions);
              await trx("OAUTH2_RoleOption").insert(insertRoleOptions);
            } catch (error) {
              throw new Error(error.message);
            }
          });
          return res.status(201).json({ code: 200000, message: "Role added" });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Create Application
    this.expressSecured.obPost(
      "/auth/application",
      "OAUTH2_application:create",
      this.validateBody({
        identifier: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { identifier } = req.body;
          await this.knex.table("OAUTH2_Applications").insert({ identifier });
          return res
            .status(201)
            .json({ code: 200000, message: "Application added" });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Create Application Part
    this.expressSecured.obPost(
      "/application/part",
      "OAUTH2_application:create",
      this.validateBody({
        partIdentifier: { type: "string" },
        applications_id: { type: "number" },
      }),
      async (req, res) => {
        try {
          const { partIdentifier, applications_id } = req.body;
          await this.knex.table("OAUTH2_ApplicationPart").insert({
            partIdentifier,
            applications_id,
          });
          return res
            .status(201)
            .json({ code: 200000, message: "Application part added" });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Create Option
    this.expressSecured.obPost(
      "/auth/option",
      "OAUTH2_option:create",
      this.validateBody({
        allowed: { type: "string" },
        applicationPart_id: { type: "number" },
      }),
      async (req, res) => {
        try {
          const { allowed, applicationPart_id } = req.body;
          await this.knex.table("OAUTH2_Options").insert({
            allowed,
            applicationPart_id,
          });
          return res
            .status(201)
            .json({ code: 200000, message: "Option added" });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Get Users
    this.expressSecured.obGet(
      "/auth/user",
      "OAUTH2_user:select",
      async (req, res) => {
        try {
          let itemsPerPage = 5;
          let pageIndex = 0;
          let order = "desc";

          if (
            req.query["itemsPerPage"] &&
            parseInt(req.query["itemsPerPage"]) >= 1
          ) {
            itemsPerPage = parseInt(req.query["itemsPerPage"]);
          }

          if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
            pageIndex = parseInt(req.query["pageIndex"]);
          }

          if (
            req.query["order"] &&
            (req.query["order"] === "desc" || req.query["order"] === "asc")
          ) {
            order = req.query["order"];
          }

          const offset = itemsPerPage * pageIndex;

          const userTotalCount = (
            await this.knex
              .table("OAUTH2_Users")
              .where("OAUTH2_Users.deleted", false)
              .count()
          )[0]["count(*)"];

          const totalPages = Math.ceil(userTotalCount / itemsPerPage);

          const users = await this.knex({
            OAUTH2_Users: this.knex("OAUTH2_Users")
              .limit(itemsPerPage)
              .offset(offset),
          })
            .select(
              "OAUTH2_Users.id",
              "OAUTH2_Users.username",
              "OAUTH2_Subjects.id as subjectId",
              "OAUTH2_Subjects.name",
              "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
              "OAUTH2_ApplicationPart.id as partId",
              "OAUTH2_Options.allowed",
              "OAUTH2_Roles.id as roleId",
              "OAUTH2_Roles.identifier as roleIdentifier"
            )
            .join(
              "OAUTH2_Subjects",
              `OAUTH2_Users.subject_id`,
              "OAUTH2_Subjects.id"
            )
            .join(
              "OAUTH2_SubjectRole",
              `OAUTH2_Users.subject_id`,
              "OAUTH2_SubjectRole.subject_id"
            )
            .join(
              "OAUTH2_Roles",
              `OAUTH2_Roles.id`,
              "OAUTH2_SubjectRole.roles_id"
            )
            .join(
              "OAUTH2_RoleOption",
              `OAUTH2_RoleOption.roles_id`,
              "OAUTH2_SubjectRole.roles_id"
            )
            .join(
              "OAUTH2_Options",
              `OAUTH2_Options.id`,
              "OAUTH2_RoleOption.options_id"
            )
            .join(
              "OAUTH2_ApplicationPart",
              `OAUTH2_ApplicationPart.id`,
              "OAUTH2_Options.applicationPart_id"
            )
            .where("OAUTH2_Users.deleted", false)
            .orderBy("id", order);

          const parsedUsers = this.parseSubjectSearch(users, "user");
          return res.status(200).json({
            code: 200000,
            message: "Select completed",
            content: {
              items: parsedUsers,
              pageIndex,
              itemsPerPage,
              totalItems: userTotalCount,
              totalPages,
            },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Get Clients
    this.expressSecured.obGet(
      "/auth/client",
      "OAUTH2_client:select",
      async (req, res) => {
        try {
          let itemsPerPage = 5;
          let pageIndex = 0;
          let order = "desc";

          if (
            req.query["itemsPerPage"] &&
            parseInt(req.query["itemsPerPage"]) >= 1
          ) {
            itemsPerPage = parseInt(req.query["itemsPerPage"]);
          }

          if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
            pageIndex = parseInt(req.query["pageIndex"]);
          }

          if (
            req.query["order"] &&
            (req.query["order"] === "desc" || req.query["order"] === "asc")
          ) {
            order = req.query["order"];
          }

          const offset = itemsPerPage * pageIndex;

          const userTotalCount = (
            await this.knex
              .table("OAUTH2_Clients")
              .where("OAUTH2_Clients.deleted", false)
              .count()
          )[0]["count(*)"];

          const totalPages = Math.ceil(userTotalCount / itemsPerPage);

          const clients = await this.knex({
            OAUTH2_Clients: this.knex("OAUTH2_Clients")
              .limit(itemsPerPage)
              .offset(offset),
          })
            .select(
              "OAUTH2_Clients.id",
              "OAUTH2_Clients.identifier",
              "OAUTH2_Subjects.id as subjectId",
              "OAUTH2_Subjects.name",
              "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
              "OAUTH2_ApplicationPart.id as partId",
              "OAUTH2_Options.allowed",
              "OAUTH2_Roles.id as roleId",
              "OAUTH2_Roles.identifier as roleIdentifier"
            )
            .join(
              "OAUTH2_Subjects",
              `OAUTH2_Clients.subject_id`,
              "OAUTH2_Subjects.id"
            )
            .join(
              "OAUTH2_SubjectRole",
              `OAUTH2_Clients.subject_id`,
              "OAUTH2_SubjectRole.subject_id"
            )
            .join(
              "OAUTH2_Roles",
              `OAUTH2_Roles.id`,
              "OAUTH2_SubjectRole.roles_id"
            )
            .join(
              "OAUTH2_RoleOption",
              `OAUTH2_RoleOption.roles_id`,
              "OAUTH2_SubjectRole.roles_id"
            )
            .join(
              "OAUTH2_Options",
              `OAUTH2_Options.id`,
              "OAUTH2_RoleOption.options_id"
            )
            .join(
              "OAUTH2_ApplicationPart",
              `OAUTH2_ApplicationPart.id`,
              "OAUTH2_Options.applicationPart_id"
            )
            .where("OAUTH2_Clients.deleted", false)
            .orderBy("id", order);

          const parsedUsers = this.parseSubjectSearch(clients, "client");

          return res.status(200).json({
            code: 200000,
            message: "Select completed",
            content: {
              items: parsedUsers,
              pageIndex,
              itemsPerPage,
              totalItems: userTotalCount,
              totalPages,
            },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Update user roles
    this.expressSecured.obPut(
      "/auth/user/role",
      "OAUTH2_user:update",
      this.validateBody({
        roles: { type: "array" },
      }),
      async (req, res) => {
        try {
          const { roles } = req.body;
          const userId = parseInt(req.query["id"]);

          const subjectRolesToInsert = roles.map((r) => {
            return { subject_id: userId, roles_id: r.id };
          });

          const result = await this.knex
            .table("OAUTH2_SubjectRole")
            .insert(subjectRolesToInsert);

          return res
            .status(201)
            .json({ code: 200000, message: "User roles added" });
        } catch (error) {
          console.log(error);
          if (error.code && error.code === "ER_DUP_ENTRY") {
            return res.status(500).json({
              code: 500000,
              message: "User already has those roles",
            });
          }
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Update client roles
    this.expressSecured.obPut(
      "/auth/client/role",
      "OAUTH2_client:update",
      this.validateBody({
        roles: { type: "array" },
      }),
      async (req, res) => {
        try {
          const { roles } = req.body;
          const userId = parseInt(req.query["id"]);

          const subjectRolesToInsert = roles.map((r) => {
            return { subject_id: userId, roles_id: r.id };
          });

          await this.knex
            .table("OAUTH2_SubjectRole")
            .insert(subjectRolesToInsert);

          return res
            .status(201)
            .json({ code: 200000, message: "Client roles added" });
        } catch (error) {
          console.log(error);
          if (error.code && error.code === "ER_DUP_ENTRY") {
            return res.status(500).json({
              code: 500000,
              message: "Client already has those roles",
            });
          }
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Delete user
    this.expressSecured.obDelete(
      "/auth/user",
      "OAUTH2_user:delete",
      async (req, res) => {
        try {
          const subjectId = req.query["subjectId"];
          if (!subjectId) {
            return res.status(400).json({
              code: 400001,
              message: "Subject id is required",
            });
          }
          if (isNaN(subjectId)) {
            return res.status(400).json({
              code: 400002,
              message: "Subject id is not a number",
            });
          }
          await this.knex.transaction(async (trx) => {
            try {
              await trx("OAUTH2_Users")
                .where({ subject_id: subjectId })
                .update("deleted", true);

              await trx("OAUTH2_Subjects")
                .where({ id: subjectId })
                .update("deleted", true);
            } catch (error) {
              throw new Error(error.message);
            }
          });

          return res.json({ code: 200000, message: "User deleted" });
        } catch (error) {
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Delete client
    this.expressSecured.obDelete(
      "/auth/client",
      "OAUTH2_client:delete",
      async (req, res) => {
        try {
          const subjectId = req.query["subjectId"];
          if (!subjectId) {
            return res.status(400).json({
              code: 400001,
              message: "Subject id is required",
            });
          }
          if (isNaN(subjectId)) {
            return res.status(400).json({
              code: 400002,
              message: "Subject id is not a number",
            });
          }
          await this.knex.transaction(async (trx) => {
            try {
              await trx("OAUTH2_Clients")
                .where({ subject_id: subjectId })
                .update("deleted", true);

              await trx("OAUTH2_Subjects")
                .where({ id: subjectId })
                .update("deleted", true);
            } catch (error) {
              throw new Error(error.message);
            }
          });

          return res.json({ code: 200000, message: "Client deleted" });
        } catch (error) {
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Delete role
    this.expressSecured.obDelete(
      "/auth/role",
      "OAUTH2_client:delete",
      async (req, res) => {
        try {
          const roleId = req.query["id"];
          if (!roleId) {
            return res.status(400).json({
              code: 400001,
              message: "Role id is required",
            });
          }
          if (isNaN(roleId)) {
            return res.status(400).json({
              code: 400002,
              message: "Role id is not a number",
            });
          }
          await this.knex
            .table("OAUTH2_Roles")
            .where({ id: roleId })
            .update("deleted", true);
          return res.json({ code: 200000, message: "Client deleted" });
        } catch (error) {
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Update user
    this.expressSecured.obPut(
      "/auth/user",
      "OAUTH2_user:update",
      this.validateBody({
        name: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { name } = req.body;
          const subjectId = req.query["subjectId"];
          if (!subjectId) {
            return res.status(400).json({
              code: 400001,
              message: "Subject id is required",
            });
          }
          if (isNaN(subjectId)) {
            return res.status(400).json({
              code: 400002,
              message: "Subject id is not a number",
            });
          }

          await this.knex
            .table("OAUTH2_Subjects")
            .where({ id: subjectId })
            .update({ name });

          return res.json({ code: 200000, message: "User updated" });
        } catch (error) {
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Update client
    this.expressSecured.obPut(
      "/auth/client",
      "OAUTH2_client:update",
      this.validateBody({
        name: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { name } = req.body;
          const subjectId = req.query["subjectId"];
          if (!subjectId) {
            return res.status(400).json({
              code: 400001,
              message: "Subject id is required",
            });
          }
          if (isNaN(subjectId)) {
            return res.status(400).json({
              code: 400002,
              message: "Subject id is not a number",
            });
          }

          await this.knex
            .table("OAUTH2_Subjects")
            .where({ id: subjectId })
            .update({ name });

          return res.json({ code: 200000, message: "Client updated" });
        } catch (error) {
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Select Roles
    this.expressSecured.obGet(
      "/auth/role",
      "OAUTH2_role:select",
      async (req, res) => {
        try {
          const basic = req.query["basic"];
          if (basic && basic == "true") {
            const roles = await this.knex
              .table("OAUTH2_Roles")
              .select("OAUTH2_Roles.id", "OAUTH2_Roles.identifier")
              .where({ deleted: false });
            return res.status(200).json({
              code: 200000,
              message: "Select completed",
              content: roles,
            });
          }
          let itemsPerPage = 5;
          let pageIndex = 0;
          let order = "desc";

          if (
            req.query["itemsPerPage"] &&
            parseInt(req.query["itemsPerPage"]) >= 1
          ) {
            itemsPerPage = parseInt(req.query["itemsPerPage"]);
          }

          if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
            pageIndex = parseInt(req.query["pageIndex"]);
          }

          if (
            req.query["order"] &&
            (req.query["order"] === "desc" || req.query["order"] === "asc")
          ) {
            order = req.query["order"];
          }

          const offset = itemsPerPage * pageIndex;

          const rolesTotalCount = (
            await this.knex
              .table("OAUTH2_Roles")
              .where("OAUTH2_Roles.deleted", false)
              .count()
          )[0]["count(*)"];

          const totalPages = Math.ceil(rolesTotalCount / itemsPerPage);

          const roles = await this.knex({
            OAUTH2_Roles: this.knex("OAUTH2_Roles")
              .limit(itemsPerPage)
              .offset(offset),
          })
            .select(
              "OAUTH2_Roles.id",
              "OAUTH2_Roles.identifier",
              "OAUTH2_ApplicationPart.id as partId",
              "OAUTH2_ApplicationPart.partIdentifier as applicationPart",
              "OAUTH2_Options.allowed",
              "OAUTH2_Options.id as optionId"
            )
            .join(
              "OAUTH2_RoleOption",
              `OAUTH2_RoleOption.roles_id`,
              "OAUTH2_Roles.id"
            )
            .join(
              "OAUTH2_Options",
              `OAUTH2_Options.id`,
              "OAUTH2_RoleOption.options_id"
            )
            .join(
              "OAUTH2_ApplicationPart",
              `OAUTH2_ApplicationPart.id`,
              "OAUTH2_Options.applicationPart_id"
            )
            .where("OAUTH2_Roles.deleted", false)
            .orderBy("OAUTH2_Roles.id", order);

          const parsedRoles = this.parseRoleSearch(roles);

          console.log("parsedRoles", parsedRoles);

          return res.status(200).json({
            code: 200000,
            message: "Select completed",
            content: {
              items: parsedRoles,
              pageIndex,
              itemsPerPage,
              totalItems: rolesTotalCount,
              totalPages,
            },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Select Parts
    this.expressSecured.obGet(
      "/auth/part",
      "OAUTH2_application:select",
      async (req, res) => {
        try {
          if (req.query["basic"] && req.query["basic"] == "true") {
            const partsSelectBasicQuery = this.knex
              .table("OAUTH2_ApplicationPart")
              .select(
                "OAUTH2_ApplicationPart.partIdentifier as applicationPartName",
                "OAUTH2_ApplicationPart.id as partId",
                "OAUTH2_Options.allowed",
                "OAUTH2_Options.id as optionId"
              )
              .join(
                "OAUTH2_Options",
                `OAUTH2_Options.applicationPart_id`,
                "OAUTH2_ApplicationPart.id"
              )
              .where("OAUTH2_ApplicationPart.deleted", false)
              .where("OAUTH2_Options.deleted", false);

            const partsBasicResult = await partsSelectBasicQuery;
            console.log(partsBasicResult);
            const parsedParts = this.parsePartSearch(partsBasicResult);

            return res.status(200).json({
              code: 200000,
              message: "Select completed",
              content: parsedParts,
            });
          }

          let itemsPerPage = 5;
          let pageIndex = 0;
          let order = "desc";

          if (
            req.query["itemsPerPage"] &&
            parseInt(req.query["itemsPerPage"]) >= 1
          ) {
            itemsPerPage = parseInt(req.query["itemsPerPage"]);
          }

          if (req.query["pageIndex"] && parseInt(req.query["pageIndex"]) >= 0) {
            pageIndex = parseInt(req.query["pageIndex"]);
          }

          if (
            req.query["order"] &&
            (req.query["order"] === "desc" || req.query["order"] === "asc")
          ) {
            order = req.query["order"];
          }

          const offset = itemsPerPage * pageIndex;

          const partsTotalCount = (
            await this.knex
              .table("OAUTH2_ApplicationPart")
              .where("OAUTH2_ApplicationPart.deleted", false)
              .count()
          )[0]["count(*)"];

          const totalPages = Math.ceil(partsTotalCount / itemsPerPage);

          const partsFullResult = await this.knex({
            OAUTH2_ApplicationPart: this.knex("OAUTH2_ApplicationPart")
              .limit(itemsPerPage)
              .offset(offset),
          })
            .select(
              "OAUTH2_ApplicationPart.partIdentifier as applicationPartName",
              "OAUTH2_ApplicationPart.id as partId",
              "OAUTH2_Options.allowed",
              "OAUTH2_Options.id as optionId"
            )
            .join(
              "OAUTH2_Options",
              `OAUTH2_Options.applicationPart_id`,
              "OAUTH2_ApplicationPart.id"
            )
            .where("OAUTH2_ApplicationPart.deleted", false)
            .where("OAUTH2_Options.deleted", false)
            .orderBy("OAUTH2_ApplicationPart.id", order)
            .orderBy("OAUTH2_Options.id", "asc");

          const parsedParts = this.parsePartSearch(partsFullResult);

          return res.status(200).json({
            code: 200000,
            message: "Select completed",
            content: {
              items: parsedParts,
              pageIndex,
              itemsPerPage,
              totalItems: partsTotalCount,
              totalPages,
            },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // Update role options
    this.expressSecured.obPut(
      "/auth/role/option",
      "OAUTH2_role:update",
      this.validateBody({
        newAllowedObject: { type: "object" },
        originalAllowedObject: { type: "object" },
      }),
      async (req, res) => {
        try {
          const { newAllowedObject, originalAllowedObject } = req.body;

          const roleId = req.query["id"];

          if (!roleId) {
            return res.status(400).json({
              code: 400001,
              message: "Identifier is required",
            });
          }

          await this.knex.transaction(async (trx) => {
            try {
              const newAllowedArray = [];
              const originalAllowedArray = [];
              const roleOptionToInsert = [];

              for (const allowed in newAllowedObject) {
                for (const a of newAllowedObject[allowed]) {
                  newAllowedArray.push({
                    roles_id: roleId,
                    options_id: a.id,
                  });
                }
              }

              for (const allowed in originalAllowedObject) {
                for (const a of originalAllowedObject[allowed]) {
                  originalAllowedArray.push({
                    roles_id: roleId,
                    options_id: a.id,
                  });
                }
              }

              for (const allowed of newAllowedArray) {
                const indexOfRoleOption = originalAllowedArray.findIndex(
                  (orp) => orp.options_id === allowed.options_id
                );
                if (indexOfRoleOption === -1) {
                  roleOptionToInsert.push(allowed);
                }
              }

              for (const allowed of originalAllowedArray) {
                const indexOfRoleOption = newAllowedArray.findIndex(
                  (orp) => orp.options_id === allowed.options_id
                );
                if (indexOfRoleOption === -1) {
                  await trx("OAUTH2_RoleOption")
                    .where({
                      roles_id: allowed.roles_id,
                      options_id: allowed.options_id,
                    })
                    .del();
                }
              }

              if (roleOptionToInsert.length !== 0) {
                await trx("OAUTH2_RoleOption").insert(roleOptionToInsert);
              }
            } catch (error) {
              throw new Error(error.message);
            }
          });

          return res.status(200).json({
            code: 200000,
            message: "Role options updated",
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );

    // LOGIN
    this.expressSecured.obPost(
      "/auth/login",
      ":",
      this.validateBody({
        username: { type: "string" },
        password: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { username, password } = req.body;
          const preUser = await this.knex
            .table("OAUTH2_Users")
            .select("OAUTH2_Subjects.name", "OAUTH2_Users.*")
            .join(
              "OAUTH2_Subjects",
              "OAUTH2_Users.subject_id",
              "OAUTH2_Subjects.id"
            )
            .where("OAUTH2_Users.username", username.toLowerCase());
          // const user = this.joinSearch(preUser, "id", "subject_id")[0];
          const correctPassword = await bcrypt.compare(
            password,
            preUser[0].password
          );
          if (!correctPassword) {
            return res.status(401).json({
              code: 400001,
              message: "Incorrect password",
            });
          }
          const token = jwt.sign(
            {
              data: {
                subjectType: "user",
                username: preUser[0].username,
              },
            },
            this.jwtSecret,
            {
              expiresIn: "24h",
              // subject: username,
            }
          );
          return res.json({
            message: `User ${username} logged in`,
            code: 200000,
            content: {
              jwt_token: token,
              username,
              name: preUser[0].name,
              userId: preUser[0].id,
            },
          });
        } catch (error) {
          console.log(error);
          return res.status(500).json({
            code: 500000,
            message: error.message,
          });
        }
      }
    );
  }

  decodeToken() {
    return (req, res, next) => {
      if (
        (req.headers &&
          req.headers.authorization &&
          req.headers.authorization.split(" ")[0] === "AK") ||
        req.query["access_token"]
      ) {
        const authToken =
          req.query["access_token"] || req.headers.authorization.split(" ")[1];
        console.log(req.headers.authorization);
        jwt.verify(authToken, this.jwtSecret, (err, decode) => {
          if (err) {
            res.locals.user = undefined;
            return res.status(401).json({
              code: 400001,
              message: "Incorrect token",
            });
          } else {
            console.log(decode.data);
            res.locals.user = decode.data;
          }
          next();
        });
      } else {
        res.locals.user = undefined;
        next();
      }
    };
  }

  guard() {
    return async (req, res, next) => {
      try {
        const exp = this.expressSecured.get(req.path);
        if (exp === ":" || exp === undefined) return next();
        const parsedExp = exp.split(":");
        if (parsedExp.length !== 2) {
          return res
            .status(403)
            .json({ code: 403200, message: "Bad guard input" });
        }
        const user = res.locals.user;
        if (!user) {
          return res
            .status(403)
            .json({ code: 403100, message: "User not authorized" });
        }
        const subjectTableToSearch =
          user.subjectType === "user" ? "OAUTH2_Users" : "OAUTH2_Clients";

        const userNameOrIdentifier =
          user.subjectType === "user" ? "username" : "identifier";

        const userAllowed = await this.knex
          .table(subjectTableToSearch)
          .select(
            "OAUTH2_Options.allowed as allowedTerm",
            "OAUTH2_ApplicationPart.partIdentifier as applicationPart"
          )
          .join(
            "OAUTH2_SubjectRole",
            `${subjectTableToSearch}.subject_id`,
            "OAUTH2_SubjectRole.subject_id"
          )
          .join(
            "OAUTH2_RoleOption",
            `OAUTH2_RoleOption.roles_id`,
            "OAUTH2_SubjectRole.roles_id"
          )
          .join(
            "OAUTH2_Options",
            `OAUTH2_Options.id`,
            "OAUTH2_RoleOption.options_id"
          )
          .join(
            "OAUTH2_ApplicationPart",
            `OAUTH2_ApplicationPart.id`,
            "OAUTH2_Options.applicationPart_id"
          )
          .where(
            `${subjectTableToSearch}.${userNameOrIdentifier}`,
            user[userNameOrIdentifier]
          );
        const patterns = this.joinSearch(
          userAllowed,
          "applicationPart",
          "allowedTerm"
        );
        const patternIndex = patterns.findIndex(
          (p) =>
            (p.applicationPart === "OAUTH2_global" &&
              p.allowedTerm.indexOf("*") !== -1) ||
            (p.applicationPart === parsedExp[0] &&
              p.allowedTerm.indexOf("*") !== -1) ||
            (p.applicationPart === parsedExp[0] &&
              p.allowedTerm.indexOf(parsedExp[1]) !== -1)
        );
        if (patternIndex !== -1) return next();
        return res
          .status(403)
          .json({ code: 403100, message: "User not authorized" });
      } catch (error) {
        console.log("thiserror", error);
        return res.status(500).json({ code: 500000, message: error.message });
      }
    };
  }

  validateBody = (validationOptions) => {
    const compareKeys = (a, b) => {
      var aKeys = Object.keys(a).sort();
      var bKeys = Object.keys(b).sort();
      return JSON.stringify(aKeys) === JSON.stringify(bKeys);
    };
    return (req, res, next) => {
      if (!compareKeys(req.body, validationOptions))
        return res.status(400).json({ code: 400000, message: "Invalid body" });

      for (const option in validationOptions) {
        switch (validationOptions[option].type) {
          case "array":
            if (!Array.isArray(req.body[option])) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an array`,
              });
            }
            break;
          case "string":
            if (
              !(
                Object.prototype.toString.call(req.body[option]) ==
                "[object String]"
              )
            ) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an string`,
              });
            }
            break;
          case "number":
            if (!!/^-?[\d.]+(?:e-?\d+)?$/.test(req.body[option])) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not a number`,
              });
            }
            break;
          case "object":
            if (!(typeof req.body[option] === "object")) {
              return res.status(400).json({
                code: 400000,
                message: `Invalid body; ${option} is not an object`,
              });
            }
            break;
          default:
            break;
        }
      }

      next();
    };
  };

  joinSearch = (baseSearch, differentiator, ...similarFields) => {
    const newArray = [];
    for (let index = 0; index < baseSearch.length; index++) {
      if (index === 0) {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          baseSearch[index][similarField] = [temporalFieldValue];
        }
        newArray.push(baseSearch[index]);
      } else if (
        baseSearch[index][differentiator] !==
        baseSearch[index - 1][differentiator]
      ) {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          baseSearch[index][similarField] = [temporalFieldValue];
        }
        newArray.push(baseSearch[index]);
      } else {
        for (const similarField of similarFields) {
          const temporalFieldValue = baseSearch[index][similarField];
          newArray[newArray.length - 1][similarField].push(temporalFieldValue);
        }
      }
    }
    return newArray;
  };

  parseSubjectSearch = (usersBaseArray, subjectType = "user") => {
    const newArray = [];
    const userNameOrIdentifier =
      subjectType === "user" ? "username" : "identifier";
    for (let index = 0; index < usersBaseArray.length; index++) {
      if (
        (usersBaseArray[index - 1] &&
          usersBaseArray[index].id !== usersBaseArray[index - 1].id) ||
        index === 0
      ) {
        const userObject = {
          id: usersBaseArray[index].id,
          subjectId: usersBaseArray[index].subjectId,
          name: usersBaseArray[index].name,
          [userNameOrIdentifier]: usersBaseArray[index][userNameOrIdentifier],
          roles: [
            {
              id: usersBaseArray[index].roleId,
              identifier: usersBaseArray[index].roleIdentifier,
              parts: [
                {
                  id: usersBaseArray[index].partId,
                  applicationPartName: usersBaseArray[index].applicationPart,
                  allowed: [usersBaseArray[index].allowed],
                },
              ],
            },
          ],
        };
        newArray.push(userObject);
      } else {
        const lastIndex = newArray.length - 1;
        const indexRole = newArray[lastIndex].roles.findIndex(
          (r) => r.id === usersBaseArray[index].roleId
        );
        if (indexRole === -1) {
          newArray[lastIndex].roles.push({
            id: usersBaseArray[index].roleId,
            identifier: usersBaseArray[index].roleIdentifier,
            parts: [
              {
                id: usersBaseArray[index].partId,
                applicationPartName: usersBaseArray[index].applicationPart,
                allowed: [usersBaseArray[index].allowed],
              },
            ],
          });
        } else {
          const indexOption = newArray[lastIndex].roles[
            indexRole
          ].parts.findIndex(
            (o) =>
              o.applicationPartName === usersBaseArray[index].applicationPart
          );
          if (indexOption === -1) {
            newArray[lastIndex].roles[indexRole].parts.push({
              id: usersBaseArray[index].partId,
              applicationPartName: usersBaseArray[index].applicationPart,
              allowed: [usersBaseArray[index].allowed],
            });
          } else {
            newArray[lastIndex].roles[indexRole].parts[
              indexOption
            ].allowed.push(usersBaseArray[index].allowed);
          }
        }
      }
    }
    return newArray;
  };

  parseRoleSearch = (rolesBaseArray) => {
    const newArray = [];
    for (let index = 0; index < rolesBaseArray.length; index++) {
      if (
        (rolesBaseArray[index - 1] &&
          rolesBaseArray[index].id !== rolesBaseArray[index - 1].id) ||
        index === 0
      ) {
        const roleObject = {
          id: rolesBaseArray[index].id,
          identifier: rolesBaseArray[index].identifier,
          parts: [
            {
              id: rolesBaseArray[index].partId,
              applicationPartName: rolesBaseArray[index].applicationPart,
              allowed: [
                {
                  allowed: rolesBaseArray[index].allowed,
                  id: rolesBaseArray[index].optionId,
                },
              ],
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const lastIndex = newArray.length - 1;
        const indexOption = newArray[lastIndex].parts.findIndex(
          (o) => o.applicationPartName === rolesBaseArray[index].applicationPart
        );
        if (indexOption === -1) {
          newArray[lastIndex].parts.push({
            id: rolesBaseArray[index].partId,
            applicationPartName: rolesBaseArray[index].applicationPart,
            allowed: [
              {
                allowed: rolesBaseArray[index].allowed,
                id: rolesBaseArray[index].optionId,
              },
            ],
          });
        } else {
          newArray[lastIndex].parts[indexOption].allowed.push({
            allowed: rolesBaseArray[index].allowed,
            id: rolesBaseArray[index].optionId,
          });
        }
      }
    }
    return newArray;
  };

  parsePartSearch = (partBaseArray) => {
    const newArray = [];
    for (let index = 0; index < partBaseArray.length; index++) {
      if (
        (partBaseArray[index - 1] &&
          partBaseArray[index].applicationPartName !==
            partBaseArray[index - 1].applicationPartName) ||
        index === 0
      ) {
        const roleObject = {
          id: partBaseArray[index].partId,
          applicationPartName: partBaseArray[index].applicationPartName,
          allowed: [
            {
              allowed: partBaseArray[index].allowed,
              id: partBaseArray[index].optionId,
            },
          ],
        };
        newArray.push(roleObject);
      } else {
        const indexOption = newArray.findIndex(
          (o) =>
            o.applicationPartName === partBaseArray[index].applicationPartName
        );
        newArray[indexOption].allowed.push({
          allowed: partBaseArray[index].allowed,
          id: partBaseArray[index].optionId,
        });
      }
    }
    return newArray;
  };
}

module.exports = OauthBoot;
