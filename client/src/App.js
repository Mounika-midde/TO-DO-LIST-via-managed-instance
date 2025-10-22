import {useState, useEffect} from 'react';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.min.css';
import Layout from './components/Layout';
import TodoForm from './components/TodoForm';
import TodoList from './components/TodoList';

function App() {
  const API = process.env.REACT_APP_BACKEND_URL;
  const [todo, setTodo] = useState('');
  const [todoList, setTodoList] = useState([]);
  const [newTodo, setNewTodo] = useState('');
  const [reload, setReload] = useState(true);

  const handleCharactersError = (value) => {
    if (value.length < 3 || value.length > 50) {
      throw new Error(
        alert(
          'Todo must have at least 3 characters and less than 50 characters.'
        )
      );
    }
  };

  const addTodo = async () => {
    handleCharactersError(todo);

    try {
      await axios.post(API+'create', {
        todo,
      }, {
        withCredentials: true
      });
    } catch (err) {
      console.error(err.message);
    }
  };

  const getAllTodos = async () => {
  
    try {
      await axios
        .get(API)
        .then((response) => {
          setTodoList(response.data);

        });
    } catch (err) {
      console.error("errro hey "+err.message);
    }
  };

  const updateTodo = async (id) => {
    handleCharactersError(newTodo);

    try {
      await axios
        .put(API+`update/${id}`, {
          id,
          todo: newTodo,
        })
        .then((response) => {
          console.log(response.data);
          setTodoList(
            todoList.map((val) =>
              val.id === id ? {id: val.id, todo: val.todo} : val
            )
          );
        });
         setReload(!reload)
    } catch (err) {
      console.error(err.message);
    }
  };

  const deleteTodo = async (id) => {
    try {
      await axios
        .delete(API+`${id}`)
        .then((response) => {
          setTodoList(todoList.filter((val) => val.id !== id));
        });
         setReload(!reload)
    } catch (err) {
      console.error(err.message);
    }
  };

  const handleSubmit = async(event) => {
    event.preventDefault();
    await addTodo();
    setTodo('');
    setReload(!reload)
    
  };

  useEffect(() => {
    getAllTodos();
  }, [reload]);

  return (
    <div className='App'>
      <Layout>
        <TodoForm handleSubmit={handleSubmit} setTodo={setTodo} todo={todo} />
        <TodoList
          todoList={todoList}
          setNewTodo={setNewTodo}
          updateTodo={updateTodo}
          deleteTodo={deleteTodo}
        />
      </Layout>

      {console.log(process.env.REACT_APP_BACKEND_URL)}
    </div>
  );
}

export default App;
