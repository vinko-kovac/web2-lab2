import express from 'express';
import fs from 'fs';
import path from 'path'
import https from 'https';
import * as auth from './middleware';
import { Pool } from 'pg'; 
import dotenv from 'dotenv'
dotenv.config()

const app = express();
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true })); 

app.set("views", path.join(__dirname, "views"));
app.set('view engine', 'pug');

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 4080;
  // auth router attaches /login, /logout, and /callback routes to the baseURL

const pool = new Pool({   
    user: process.env.DB_USER,   
    host: process.env.DB_HOST,   
    database: 'web2_lab1_db',   
    password: process.env.DB_PASSWORD,   
    port: 5432,   
    ssl : true
})

var crypto = require('crypto');

var generate_key = function() {
    return crypto.randomBytes(16).toString('base64');
}

var sessionId = generate_key();

var secureSession = "";

auth.initCookieAuth(app, 'broken');

app.get('/', function (req, res) {
    res.render('index');
})

app.get('/injection', function (req, res) {
    res.render('injection');
})

app.post('/search', async function (req, res) {
    const name = req.body.compname;
    let result;
    if (req.body.check == "false") {
        result = await pool.query(`SELECT name, userid FROM competition WHERE name='${name}'`);
    } else {
        result = await pool.query('SELECT name, userid FROM competition WHERE name=$1', [name]);
    }

    res.render('show', {rows: result.rows});
})

app.get('/broken', function (req, res) {
    res.render('broken');
})

app.post('/login', function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    if (req.body.check == "false") {
        if (username == "bob" && password == "pass") {
            sessionId = generate_key();
            res.redirect('/unsecurePrivate?sessionId='+sessionId);
        } else {
            res.redirect('/broken');
        }
    } else {
        if (username == "bob" && password == "pass") {
            secureSession = generate_key();
            auth.signInUser(res, username, secureSession);
            res.redirect('/securePrivate')
        }
        else {
            res.redirect('/broken');
        }
    }
})

app.get('/unsecurePrivate', function(req, res) {
    if (req.query.sessionId == sessionId) {
        res.render('private', {user: "bob", t: true});
    } else {
        res.render('error', {message: "Wrong username or password"});
    }
})

app.post('/unsecureLogout', function(req, res) {
    res.redirect('/broken');
})

app.get('/securePrivate', auth.requiresAuthentication, function (req, res) {   
    const username = req.user!.username;
    const session = req.user!.session;
    const timestamp = req.user!.timestamp;
    if (session == secureSession && secureSession != "") {
        if ((Date.now() - timestamp) < 120000) {
            let newSession = generate_key();
            secureSession = newSession;
            auth.changeSession(res, newSession);
            res.render('private', {user: username, t: false});
        } else {
            auth.signOutUser(res);
            res.redirect('/broken');
        }        
    }
    else {
        res.render('error', {message: "Wrong username or password"});
    }       
});

app.post('/secureLogout',   function (req, res) {
    secureSession = "";
    auth.signOutUser(res);
    res.redirect('/broken');
});






if (externalUrl) {
    const hostname = '0.0.0.0';
    app.listen(port, hostname, () => {
      console.log(`Server locally running at http://${hostname}:${port}/ and from outside on ${externalUrl}`);
    });
  } else {
    https.createServer({
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.cert')
        }, app)
        .listen(port, function () {
          console.log(`Server running at https://localhost:${port}/`);
    });
  }