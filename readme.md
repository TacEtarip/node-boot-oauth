# nodeboot-oauth2-starter

You can use this library in any express project to secure your endpoints. To do this you will need a mysql database.

## Access control string

An string that validates that a subject has the permission to access determinate endpoint. Has the following form `applicationPart:option`. You will need to pass this string like a middleware after using the library wrapper.

```javascript
app.get('/api/someEndPoint', 'applicationPart:option', (req, res) => ...)
```

## Database

The library will ask for a knex connection to mysql, given that will create 6 main tables to manage your application security.

### Tables

| Table                  | Description                                                                                                          |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------- |
| OAUTH2_Subjects        | A user or client of the application, a subject can access or use different entities or processes of the application. |
| OAUTH2_Users           | An user of the application will have an username and a password.                                                     |
| OAUTH2_Clients         | A client of the application that will access it with an access_token.                                                |
| OAUTH2_Applications    | A list of the applications that this database supports.                                                              |
| OAUTH2_ApplicationPart | The entities or processes that an application has.                                                                   |
| OAUTH2_Options         | The access options that each `OAUTH2_ApplicationPart` has.                                                           |

### OAUTH2_ApplicationPart, OAUTH2_Options and how to secure your endpoints

Lets suppose that you have an store application named `superbuy` and that you have the following processes, entities or parts:

- Sales
- Products
- Read accounting excel

For _Sales_ you will create a `sales` column in the table `OAUTH2_ApplicationPart`, for _Products_ a `products` one and finally for _Read accounting excel_ `read_accounting_excel`.
Each column will be create with at least those five options that will be put in the table `OAUTH2_Options`:

- _\*_
- create
- update
- delete
- select

Then for example to protect sales you will need to use an access control string:

| Method   | Url   | Access control string |
| -------- | ----- | --------------------- |
| `POST`   | /sale | sales:create          |
| `GET`    | /sale | sales:select          |
| `PUT`    | /sale | sales:update          |
| `DELETE` | /sale | sales:delete          |

In the case of the process you can either use any of the access control string like `read_accounting_excel:create` or create a new option like _process_ and use it `read_accounting_excel:process`, it is up to you.

### Why do it this way and not only in options have the access control string?

Why not just save the string in one table instead of divided it in two tables.

The primary reason is it the possibility to have this:

![alt text](https://i.ibb.co/t2T5FSF/WQEGG.png)

Along side been able to group the options by category giving it more order.
