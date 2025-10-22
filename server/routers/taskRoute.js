// server/routes/taskRoute.js
const { Router } = require('express');
const { TodoRecord } = require('../records/todo.record');

const TodoRouter = Router();

TodoRouter.get('/', async (req, res) => {
  try{
    const todosList = await TodoRecord.listAll();
    console.log("Data feteched")
    res.status(200).send(todosList)
  }
  catch(err){
    console.error("Data feteching error")
    res.status(400).send("error hey" + err.message);
  }
  
});

TodoRouter.get("/health",(req,res)=>{
  res.status(200).send("OK");
})

TodoRouter.post('/create', async (req, res) => {
  const newTodo = new TodoRecord(req.body);
  await newTodo.insert();
  console.log("Data inserted")

  res.send('Values inserted successfully');
});

TodoRouter.delete('/:id', async (req, res) => {
  const todo = await TodoRecord.getOne(req.params.id);
  await todo.delete();
  console.log("Data deleted")
  res.send('Deleted successfully');
});

TodoRouter.put('/update/:id', async (req, res) => {
  const todo = await TodoRecord.getOne(req.params.id);
  await todo.update(req.body.id, req.body.todo);
  console.log("Data updated")
  res.send('Updated successfully');
});

module.exports = {
  TodoRouter,
};
