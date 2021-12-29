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
          applications_id: {
            defaultValue: null,
            type: "int",
            maxLength: null,
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
        OAUTH2_ApplicationOption: {
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
          applications_id: {
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
          allowed: {
            defaultValue: null,
            type: "varchar",
            maxLength: 75,
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

      if (falseCount > 0) {
        await this.createTables();
      } else {
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
              console.log(`Table ${tableExpected} inconsistencies in columns:`);
              for (const inconsistency of inconsistencies) {
                console.log(inconsistency + "/n");
              }
              console.log("Tables will be created from 0");
              await this.createTables();
            }
          }
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
      await this.knex.schema.createTable("OAUTH2_Subjects", (table) => {
        table.increments("id");
        table.string("name", 45).notNullable();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Users", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.string("username", 45).notNullable().unique();
        table.string("password", 75).notNullable();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Clients", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.string("identifier", 100).notNullable().unique();
        table.string("access_token", 255).notNullable();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Options", (table) => {
        table.increments("id");
        table.string("allowed", 75).notNullable().unique();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Applications", (table) => {
        table.increments("id");
        table.string("identifier", 100).notNullable().unique();
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_Roles", (table) => {
        table.increments("id");
        table.string("identifier", 100).notNullable().unique();
        table.integer("applications_id").unsigned().notNullable();
        table.foreign("applications_id").references("OAUTH2_Applications.id");
        table.timestamps(true, true);
      });

      await this.knex.schema.createTable("OAUTH2_SubjectRole", (table) => {
        table.increments("id");
        table.integer("subject_id").unsigned().notNullable();
        table.foreign("subject_id").references("OAUTH2_Subjects.id");
        table.integer("roles_id").unsigned().notNullable();
        table.foreign("roles_id").references("OAUTH2_Roles.id");
      });

      await this.knex.schema.createTable(
        "OAUTH2_ApplicationOption",
        (table) => {
          table.increments("id");
          table.integer("options_id").unsigned().notNullable();
          table.foreign("options_id").references("OAUTH2_Options.id");
          table.integer("applications_id").unsigned().notNullable();
          table.foreign("applications_id").references("OAUTH2_Applications.id");
        }
      );
      await this.knex.transaction(async (trx) => {
        try {
          const masterId = await trx("OAUTH2_Applications").insert({
            identifier: "masterApp",
          });

          const optionId = await trx("OAUTH2_Options").insert({
            allowed: "*:*",
          });

          await trx("OAUTH2_ApplicationOption").insert({
            options_id: optionId[0],
            applications_id: masterId[0],
          });

          const roleId = await trx("OAUTH2_Roles").insert({
            applications_id: masterId[0],
            identifier: "masterAdmin",
          });

          const subjectId = await trx("OAUTH2_Subjects").insert({
            name: "Master Admin",
          });

          await trx("OAUTH2_SubjectRole").insert({
            subject_id: subjectId[0],
            roles_id: roleId[0],
          });

          const password = randomstring.generate();

          const encryptedPassword = await bcrypt.hash(password, 16);

          await trx("OAUTH2_Users").insert({
            username: "admin",
            password: encryptedPassword,
            subject_id: subjectId,
          });

          console.log("Created file credentials.txt in the cwd");

          await fs.writeFile(
            path.join(process.cwd(), "/credentials.txt"),
            `Dont lose this file or the credentials in it.\n
              Username: admin \n
              Password: ${password}`
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
        "OAUTH2_ApplicationOption",
        "OAUTH2_Roles",
        "OAUTH2_Applications",
        "OAUTH2_Options",
      ];
      for (const tableName of tablesToDropInOrder) {
        await this.knex.schema.dropTableIfExists(tableName);
      }
    } catch (error) {
      throw new Error(error.message);
    }
  }

  // { defaultValue: null, type: 'int', maxLength: null, nullable: false }

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

    // expressApp.put = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressApp.obDelete = (path, allowed, ...handler) => {
      expressApp.set(path, allowed);
      return expressApp.delete(path, ...handler);
    };

    // console.log("xx");
    return expressApp;
  }

  static bootOauthExpressRouter(expressRouter) {
    // expressApp.post = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressRouter.obGet = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.get(path, ...handler);
    };

    // expressApp.put = (path, allowed, ...handler) => {
    //   expressApp.set(path, allowed);
    //   return expressApp.post(path, ...handler);
    // };

    expressRouter.obDelete = (path, allowed, ...handler) => {
      expressRouter.set(path, allowed);
      return expressRouter.delete(path, ...handler);
    };

    // console.log("xx");
    return expressRouter;
  }

  addEndPoints() {
    this.expressSecured.post(
      "/user",
      this.validateBody({
        username: { type: "string" },
        password: { type: "string" },
        name: { type: "string" },
      }),
      async (req, res) => {
        try {
          const { username, password, name } = req.body;
          const encryptedPassword = await bcrypt.hash(password, 10);

          await this.knex.transaction(async (trx) => {
            try {
              const firstResult = await this.knex
                .insert({ name })
                .into("OAUTH2_Subjects")
                .transacting(trx);
              const secondResult = await this.knex
                .insert({
                  username,
                  password: encryptedPassword,
                  subject_id: firstResult[0],
                })
                .into("OAUTH2_Users")
                .transacting(trx);
              console.log(secondResult);
              trx.commit();
            } catch (error) {
              trx.rollback();
              console.log(error);
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

    this.expressSecured.obPost(
      "/login",
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
            .select("OAUTH2_SubjectRole.id as subjectRoleId", "OAUTH2_Users.*")
            .join(
              "OAUTH2_SubjectRole",
              "OAUTH2_Users.subject_id",
              "OAUTH2_SubjectRole.subject_id"
            )
            .where("OAUTH2_Users.username", username);
          const user = this.joinSearch(preUser, "id", "subject_id");
          const correctPassword = await bcrypt.compare(
            password,
            user[0].password
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
                id: user.id,
                username: user.username,
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
            content: { jwt_token: token },
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
        req.headers &&
        req.headers.authorization &&
        req.headers.authorization.split(" ")[0] === "AK"
      ) {
        const auth = req.headers.authorization;
        console.log(req.headers.authorization);
        jwt.verify(
          auth.split(" ")[1],
          this.jwtSecret,
          // { audience: auth.split(" ")[2] + " " + auth.split(" ")[3] },
          (err, decode) => {
            if (err) {
              res.locals.user = undefined;
              return res.status(401).json({
                code: 400001,
                message: "Incorrect token",
              });
            } else {
              res.locals.user = decode;
            }
            next();
          }
        );
      } else {
        res.locals.user = undefined;
        next();
      }
    };
  }

  guard() {
    return (req, res, next) => {
      console.log(req.path);
      console.log("user", res.locals.user);
      const exp = this.expressSecured.get(req.path);
      console.log(exp);
      next();
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
}

module.exports = OauthBoot;
