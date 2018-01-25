# WildDuck Mail Service

**What is this?**

This is an example web service that uses the [Wild Duck API](https://github.com/nodemailer/wildduck/wiki/API-Docs) to manage user settings and preview messages.

## Live demo

There's a live demo up at https://wildduck.email

## Usage

Assuming that you have Wild Duck mail server running

```
$ npm install
$ npm run bowerdeps
$ node server.js
```

You can also create an additional service specific configuration file that would be merged with the default config.

```
$ node server.js --config="/etc/wildduck/www.toml"
```

After you have started the server, head to http://localhost:3000/

## Screenshots

![](https://raw.githubusercontent.com/nodemailer/wildduck-webmail/master/public/demo/img01.png)

![](https://raw.githubusercontent.com/nodemailer/wildduck-webmail/master/public/demo/img02.png)

![](https://raw.githubusercontent.com/nodemailer/wildduck-webmail/master/public/demo/img03.png)

![](https://raw.githubusercontent.com/nodemailer/wildduck-webmail/master/public/demo/img04.png)

![](https://raw.githubusercontent.com/nodemailer/wildduck-webmail/master/public/demo/img05.png)

## License

[European Union Public License 1.1](http://ec.europa.eu/idabc/eupl.html) or later.
