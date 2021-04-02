require('dotenv').config();

var nodemailer = require('nodemailer');
const express = require('express');
const app = express();
app.use(express.json());

const {authenticate} = require('./authorize');


const mongodb = require('mongodb');
const mongoClient = mongodb.MongoClient;
const objectid = mongodb.ObjectId;
const bcrypt =require('bcrypt');

const jwt = require('jsonwebtoken');

const port = process.env.PORT || 8080;
const dburl = process.env.DB_URL || ' mongodb://127.0.0.1:27017'

// Api route for Admin registeration

app.post ('/admin-register',async(req,res)=>
{
    try{
 
    let client = await mongoClient.connect(dburl);
    let db = client.db('movieBookingAppUsers');
    let adminExist = await db.collection('admin').findOne({"email" : req.body.email});
    if(adminExist)
    {
        res.status(400).json({'message':'U are already an admin!!'})
    }
    else{
           let salt = await bcrypt.genSalt();
           let hashedpassword  = await bcrypt.hash(req.body.password,salt);
           let hashedcpassword  = await bcrypt.hash(req.body.password,salt);
           console.log(salt);
           console.log(hashedpassword);
           req.body.password=hashedpassword;
           req.body.cpassword=hashedcpassword;
           console.log(req.body);
           let newadmin = await db.collection('admin').insertOne(req.body);
  
           res.status(200).json({'message':'admin created successfully!!!'});
      
    }
    client.close();
    }catch(error)
    {
        console.log(error);
    }
})

// Api route for user registeration

app.post ('/user-register',async(req,res)=>
{
    try{
 
    let client = await mongoClient.connect(dburl);
    let db = client.db('movieBookingAppUsers');
    let adminExist = await db.collection('users').findOne({"email" : req.body.email});
    if(adminExist)
    {
        res.status(404).json({'message':'email already exists!!'})
    }
    else{
           let salt = await bcrypt.genSalt();
           let hashedpassword  = await bcrypt.hash(req.body.password,salt);
           let hashedcpassword  = await bcrypt.hash(req.body.password,salt);
           console.log(salt);
           console.log(hashedpassword);
           req.body.password=hashedpassword;
           req.body.cpassword=hashedcpassword;
           console.log(req.body);
           let newuser = await db.collection('users').insertOne(req.body);
  
           res.status(201).json({'message':'user registered successfully!!!'});
      
    }
    client.close();
    }catch(error)
    {
        console.log(error);
    }
})

//Api route for user and admin login

app.post ('/login',async(req,res)=>
{
    try{

   let client = await mongoClient.connect(dburl);
   let db = client.db('movieBookingAppUsers');
   console.log( req.body.email);
   let admin =  await db.collection('admin').findOne({"email": req.body.email});
   
   let user = await db.collection('users').findOne({"email": req.body.email});

   if(admin)
   {
       let token = await jwt.sign({id : admin._id,username : admin.username},process.env.JWT_SECRET)
       let Isvalid= await bcrypt.compare(req.body.password,admin.password);

       if(Isvalid && req.body.password === req.body.cpassword)
       {
           console.log(token);
           await db.collection('admin').update({"email":req.body.email},{$push : {"tokens":[admin._id,token]}});
           res.status(200).json({'message' : 'login successful!!!',token})
       }
       else{
           res.status(400).json({'message':'login unsuccessful!!!'})
       } 
   }
   else if(user){
      
    if(user)
    {
        let token = await jwt.sign({id : user._id,username : user.username},process.env.JWT_KEY)
        let Isvalid1= await bcrypt.compare(req.body.password,user.password)
        console.log(req.body.password)
        if(Isvalid1 && req.body.password === req.body.cpassword )
        {
            console.log(token);
            await db.collection('users').update({"email":req.body.email},{$push : {"tokens":[user._id,token]}});
            res.status(200).json({'message' : 'login successful!!!',token})
        }
        else{
            res.status(400).json({'message':'login unsuccessful!!!'})
        } 
    }
 else{
        res.status(404).json({'message':'user doesnot exist, kindly register!!'})
      
    }
   }else{

    res.status(404).json({'message':'Invalid credentials!!'})

   }

   
    client.close();
    }catch(error)
    {
        console.log(error);
    }
});





app.listen(port,()=>{
    console.log("App started!!!!");
  console.log(`App is running in PORT: ${port}`);
    
})
