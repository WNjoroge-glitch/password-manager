const express = require('express');
const app = express();
const ejs = require('ejs');
const mysql = require('mysql')
const bcrypt = require('bcryptjs')
const crypto = require('crypto-js')
const session = require('express-session')
require('dotenv').config()

app.use(
    session({
       secret:'secret message',
       resave:false,
       saveUninitialized:false
  })
)



const db = mysql.createConnection({
    host:'localhost',
    user:'root',
    port:'3306',
    password:'sqlpassword1#',
    database:'password_manager'
})

db.connect()

app.use(express.static("public"));

//config to get access to form values
app.use(express.urlencoded({extended:false}))


app.set('views','./views')
app.set('view engine','ejs')

app.use((req,res,next)=>{
    if(req.session.userId === undefined){
        res.locals.isLoggedIn = false;
    } else {
    res.locals.isLoggedIn = true
        res.locals.email = req.session.email
        }
     next()
})


app.get('/',(req,res) =>{
    res.render('join')
})
app.get('/main',(req,res)=>{

    if(res.locals.isLoggedIn){
        
        db.query('SELECT * FROM user_details WHERE user_id = ?', req.session.userId,(error,result) =>{
            if(error){
                console.log(error)
            } else {
              res.render('main', {results:result})
            }
            
            
        })

    } else {
        res.redirect('/login')
    }
})


app.get('/form',(req,res)=>{
    res.locals.isLoggedIn ? res.render('form') : res.redirect('/login')
    
})

app.post('/form',(req,res)=>{
    const name= req.body.name
    const url = req.body.url
    const password = req.body.password
    const user = req.body.user

    //encrypt password
   
   const secretKey = process.env.ENCRYPTION_KEY
   const encryptedPassword = crypto.AES.encrypt(password,secretKey).toString()


    const sqlQuery = 'INSERT INTO user_details(name,username,url,password_name) VALUES(?,?,?,?);'

    db.query(sqlQuery,[name,user,url,encryptedPassword],(error,result) =>{
        if(error){
            console.log(error)
        } else{
            res.redirect('main')
        }
    })
    
})


app.get('/signup', (req,res)=>{
    res.render('signup')
})


app.post('/signup', async (req,res) => {
    const email = req.body.email
    const password = req.body.password
    const confirmPassword = req.body.confirmpassword
//hash password
    
    const sqlQuery = 'INSERT INTO signup_details(email,password) VALUES(?,?);'

    if (password !== confirmPassword){
        res.status(400).send("passwords do not match")
    } else {
        bcrypt.hash(password,10,(error,hash) =>{
            db.query(sqlQuery,[email,hash],
                res.redirect('/login')
            )
        })

        }
    }
)
    

app.get('/login',(req,res) =>{
    res.render('login')
})

app.post('/login', (req,res) =>{
    const email = req.body.email
    const password = req.body.password

    

    db.query('SELECT * FROM signup_details WHERE email = ?',email,(error,results)=>{
        bcrypt.compare(password,results[0].password,(error,isEqual) =>{
           if(isEqual){
                 req.session.userId = results[0].id
                 req.session.email = results[0].email
                 res.redirect('/main')
              } else {
                 res.redirect('/login')
              }
            })
        
     })
})
           



app.get('/main/:id',(req,res) => {
    //decrypt password 

    if(res.locals.isLoggedIn){
        const id = Number(req.params.id)
    
        const sqlQuery = `SELECT * from user_details WHERE id = ${id};`
        db.query(sqlQuery,(error,result) => {
            const secretKey =process.env.ENCRYPTION_KEY
            const password = result[0].password_name
            const decrypt = crypto.AES.decrypt(password,secretKey)
            const decryptedPassword = decrypt.toString(crypto.enc.Utf8)
           
            
            res.render('details', {details:result,password:decryptedPassword})
        })

    } else {
        res.redirect('/login')
    }
    
   
})
app.post('/delete/:id',(req,res)=>{
    const id = Number(req.params.id)
    

    db.query('DELETE FROM user_details WHERE id = ?',id,(error,result)=>{
        if(error){
            console.log(error)
        }
        else {
           
            res.redirect('/main')
        }
    })
})

app.get('/logout',(req,res)=>{
    req.session.destroy((error) =>{
        
        res.redirect('/')
     })
})

app.listen("3002", ()=>{console.log("server started")})

