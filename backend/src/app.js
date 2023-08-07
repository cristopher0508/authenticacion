const express = require("express");
const session = require("express-session");
const BodyParser = require("body-parser");
const Cookie = require("cookie-parser");
const bcrypt = require('bcrypt')
const morgan = require("morgan");
const mysql = require('mysql')
const app = express()
const cors = require('cors')


app.use(BodyParser.json())
app.use(BodyParser.urlencoded({extended: false}))
app.use(morgan('dev'))
app.use(Cookie())
app.use(session({
    secret : "secret",
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 * 24
    }
}))

app.use(cors({
    origin : ['http://localhost:3000'],
    credentials: true,
    methods: ["POST", "GET"]
    
}))


const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database : 'signup'
})

app.get('/', (req, res)=>{
    if(req.session.username) {
        return res.json({valid:true, user: req.session.username})

    }
})


app.post('/signup', (req, res)=>{
    const sql = "INSERT INTO users (`username`,`email`,`password`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), bcrypt.genSaltSync(10), (err, hash)=>{
        if (err) return res.json({error: "Error for hassing password"});
        const values = [
            req.body.username,
            req.body.email,
            hash
        ]
        db.query(sql, [values], (err, result)=>{
            if(err) return res.json({Error: "Inserting data error in server"})
            return res.json({Status: "success", result: result});
        })
    })
})

app.post('/signin', (req, res)=>{
    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [req.body.email], (err, result)=>{
        if (err) return res.json({Error: 'Hubo un error en el servidor'})
        if(result.length > 0){
            bcrypt.compare(req.body.password.toString(), result[0].password, (err, response)=>{
                if(err) return res.json({Error:'Password compare error'});
                if(response) {
                    req.session.username = result[0].username;
                    req.session.id = result[0].id;
                    console.log(req.session.id)
                    console.log(req.session.username)
                    return res.json({Status: 'success', Login: true})
                }else{
                    return res.json({Error: 'password not mached'})
                }
            })
        }else{
            return res.json({Error: "Email not exist"})
        }
    })
})

app.listen(8081, ()=>{
    console.log("Server on Port 8081")
})

