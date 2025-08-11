const express = require('express')
const app = express()
const port = process.env.PORT || 3000
const cors = require("cors");
require("dotenv").config();

app.use(cors())
app.use(express.json())

app.get('/', (req,res)=>{
    res.send('hello i am flight server')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})