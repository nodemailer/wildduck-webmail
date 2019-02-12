# WildDuck Mail Service

**What is this?**

This is the default web service for [WildDuck email server](https://wildduck.email). The web service uses the [Wild Duck API](https://github.com/nodemailer/wildduck/wiki/API-Docs) to manage user settings and preview messages.

## Live demo

There's a live demo up at https://wildduck.email – you can register a free @wildduck.email email address and try it out as a real email account.

## Usage

Assuming that you have [WildDuck email server](https://wildduck.email) already running (check out [quick setup](https://github.com/nodemailer/wildduck/tree/master/setup)):

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

### Message verification

Message verification displays information about DKIM signature, SPF domain and TLS status in the last hop of transit.

**Everything is OK:**

![](https://cldup.com/GhuFvNx5Js.png)

**Sender did not use TLS**

![](https://cldup.com/pUgzVxpMFW.png)

## License

[European Union Public License 1.1](http://ec.europa.eu/idabc/eupl.html) or later.
