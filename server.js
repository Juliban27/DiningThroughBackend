import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
import { PORT, DB_URI, JWT_SECRET, CLIENT_ORIGIN, SALT_ROUNDS } from './config.js';

const app = express();

const whitelist = [
  process.env.CLIENT_ORIGIN,      // e.g. 'https://dining-through.vercel.app'
  'http://localhost:5173'
];

mongoose.connect(DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conectado a MongoDB Atlas'))
    .catch(err => console.error('Error al conectar a MongoDB:', err));


app.use(cors({
  origin: (origin, cb) => {
    // permite también peticiones sin origin (ej. Postman)
    if (!origin || whitelist.includes(origin)) return cb(null, true);
    cb(new Error('CORS no permitido'), false);
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: true
}));

app.use(express.json());

// Conectar a MongoDB Atlas
mongoose.connect('DB_URI', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conectado a MongoDB Atlas'))
    .catch(err => console.error('Error al conectar a MongoDB:', err));

const User = mongoose.model('User', {
    id: String,
    email: String,
    password: String,
    role: String,
    name: String,
});

const Product = mongoose.model('Product', {
    product_id: String,
    name: String,
    description: String,
    price: Number,
    stock: Number,
    alergies: Array,
    image: String,
    category: String,
    restaurant_id: Array,
    calification: Number,
});

const Order = mongoose.model('Order', {
    order_id: String,
    client_id: String,
    bill_id: String,
    punto_venta: String,
    products: Array,
    state: String,
    date: Date
});

const Bill = mongoose.model('Bill', {
    bill_id: String,
    client_id: String,
    products: Array,
    date: Date,
    total: Number,
    state: String
});

const Restaurant = mongoose.model('Restaurant', {
    restaurant_id: String,
    name: String,
    location: String,
    hora_apertura: String,
    hora_cierre: String,
    image: String,
    latitude: Number,
    longitude: Number,
})

const Rating = mongoose.model('Rating', {
    product_id: String,
    user_id: String,
    score: Number,
    comment: String,
    date: Date,
});


// Ruta de prueba
app.get('/', (req, res) => {
    res.send('Backend funcionando');
});

// Ruta para obtener todos los usuarios
app.get('/users', async (req, res) => {
    try {
        const users = await User.find();
        res.json(users);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener los usuarios' });
    }
});

// Ruta para obtener un usuario por ID
app.get('/users/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el usuario' });
    }
});

// Ruta para agregar un usuario
app.post('/users', async (req, res) => {
    try {
        const user = new User(req.body);
        await user.save();
        res.status(201).json(user);
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el usuario' });
    }
});


//Productos/////////////////////////////

// Ruta para obtener todos los productos
app.get('/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener los productos' });
    }
});

//Ruta para patch los productos

app.patch('/products/:id', async (req, res) => {
  try {
    const updates = req.body; // { stock: nuevoValor }
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: true }
    );
    if (!product) return res.status(404).json({ error: 'Producto no encontrado' });
    res.json(product);
  } catch (error) {
    console.error('Error al actualizar inventario:', error);
    res.status(500).json({ error: 'Error al actualizar el inventario' });
  }
});

// Ruta para agregar un nuevo producto
app.post('/products', async (req, res) => {
    try {
        const product = new Product(req.body);
        await product.save();
        res.status(201).json(product);
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el producto' });
    }
});

// Ruta para obtener un producto por su ID
app.get('/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: 'Producto no encontrado' });
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el producto' });
    }
});

// Ruta para actualizar un producto
app.put('/products/:id', async (req, res) => {
    try {
        const product = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!product) return res.status(404).json({ error: 'Producto no encontrado' });
        res.json(product);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar el producto' });
    }
});

// Ruta para eliminar un producto
app.delete('/products/:id', async (req, res) => {
    try {
        const product = await Product.findByIdAndDelete(req.params.id);
        if (!product) return res.status(404).json({ error: 'Producto no encontrado' });
        res.json({ message: 'Producto eliminado' });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar el producto' });
    }
});

// Order//////////////////////////


// Ruta para obtener todos los pedidos
app.get('/orders', async (req, res) => {
    try {
        const orders = await Order.find();
        res.json(orders);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener los pedidos' });
    }
});

// Ruta para agregar un nuevo pedido
app.post('/orders', async (req, res) => {
    try {
        const order = new Order(req.body);
        await order.save();
        res.status(201).json(order);
    } catch (error) {
        res.status(500).json({ error: 'Error al guardar el pedido' });
    }
});

// Ruta para obtener un pedido por su ID
app.get('/orders/:id', async (req, res) => {
    try {
        const order = await Order.findById(req.params.id);
        if (!order) return res.status(404).json({ error: 'Pedido no encontrado' });
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el pedido' });
    }
});

// Ruta para actualizar un pedido
app.put('/orders/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!order) return res.status(404).json({ error: 'Pedido no encontrado' });
        res.json(order);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar el pedido' });
    }
});

// Ruta para eliminar un pedido
app.delete('/orders/:id', async (req, res) => {
    try {
        const order = await Order.findByIdAndDelete(req.params.id);
        if (!order) return res.status(404).json({ error: 'Pedido no encontrado' });
        res.json({ message: 'Pedido eliminado' });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar el pedido' });
    }
});



////////Bills////////////

// Ruta para obtener todas las facturas
app.get('/bills', async (req, res) => {
    try {
        const bills = await Bill.find();
        res.json(bills);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener las facturas' });
    }
});

// Ruta para agregar una nueva factura
// POST /bills  ─ bill_id = (facturas existentes) + 1
app.post('/bills', async (req, res) => {
  try {
    // 1) ¿Cuántas facturas hay ahora?
    const totalBills = await Bill.countDocuments();

    // 2) Creamos la nueva factura con bill_id autoincremental
    const newBill = await Bill.create({
      ...req.body,
      bill_id: (totalBills + 1).toString(),
      date   : new Date(),
    });

    res.status(201).json(newBill);
  } catch (error) {
    res.status(500).json({ error: 'Error al guardar la factura' });
  }
});


// Ruta para obtener una factura por su ID
app.get('/bills/:id', async (req, res) => {
    try {
        const bill = await Bill.findById(req.params.id);
        if (!bill) return res.status(404).json({ error: 'Factura no encontrada' });
        res.json(bill);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener la factura' });
    }
});

// Ruta para actualizar una factura
app.put('/bills/:id', async (req, res) => {
    try {
        const bill = await Bill.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!bill) return res.status(404).json({ error: 'Factura no encontrada' });
        res.json(bill);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar la factura' });
    }
});

// Ruta para eliminar una factura
app.delete('/bills/:id', async (req, res) => {
    try {
        const bill = await Bill.findByIdAndDelete(req.params.id);
        if (!bill) return res.status(404).json({ error: 'Factura no encontrada' });
        res.json({ message: 'Factura eliminada' });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar la factura' });
    }
});

//////Restaurants///////
app.get('/restaurants', async (req, res) => {
    try {
        const restaurants = await Restaurant.find();
        res.json(restaurants);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener los restaurantes' });
    }
});

// Ruta para agregar un nuevo restaurante
app.post('/restaurants', async (req, res) => {
    console.log('📥 Payload recibido en /restaurants:', req.body);
    try {
        const restaurant = await Restaurant.create(req.body);
        console.log('✅ Restaurante creado:', restaurant);
        return res.status(201).json(restaurant);
    } catch (error) {
        console.error('💥 Error al guardar restaurante:', error);
        return res.status(500).json({ error: error.message });
    }
});

// Ruta para obtener un restaurante por su ID
app.get('/restaurants/:id', async (req, res) => {
    try {
        const restaurant = await Restaurant.findById(req.params.id);
        if (!restaurant) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json(restaurant);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el restaurante' });
    }
});

// Ruta para actualizar un restaurante
app.put('/restaurants/:id', async (req, res) => {
    try {
        const restaurant = await Restaurant.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!restaurant) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json(restaurant);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar el restaurante' });
    }
});

// Ruta para eliminar un restaurante
app.delete('/restaurants/:id', async (req, res) => {
    try {
        const restaurant = await Restaurant.findByIdAndDelete(req.params.id);
        if (!restaurant) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json({ message: 'Restaurante eliminado' });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar el restaurante' });
    }
});

// Ruta para obtener el horario de un restaurante
app.get('/restaurants/:id/horario', async (req, res) => {
    try {
        const { hora_apertura, hora_cierre } = await Restaurant.findById(
            req.params.id,
            'hora_apertura hora_cierre'          // solo esos campos
        );
        if (!hora_apertura) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json({ hora_apertura, hora_cierre });
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener el horario' });
    }
});

// Actualizar la hora de apertura y/o cierre
app.patch('/restaurants/:id/horario', async (req, res) => {
    try {
        const { hora_apertura, hora_cierre } = req.body;

        const updates = {};
        if (hora_apertura) updates.hora_apertura = hora_apertura;
        if (hora_cierre) updates.hora_cierre = hora_cierre;

        const restaurant = await Restaurant.findByIdAndUpdate(
            req.params.id,
            { $set: updates },
            { new: true, runValidators: true }
        );

        if (!restaurant) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json({
            mensaje: 'Horario actualizado',
            hora_apertura: restaurant.hora_apertura,
            hora_cierre: restaurant.hora_cierre
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar el horario' });
    }
});

// Ruta para obtener la imagen de un restaurante
app.get('/restaurants/:id/imagen', async (req, res) => {
    try {
        const { image } = await Restaurant.findById(req.params.id, 'image').lean();
        if (!image) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json({ image });
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener la imagen' });
    }
});

// Ruta para obtener el nombre de un restaurante
app.get('/restaurants/:id/nombre', async (req, res) => {
    try {
        const doc = await Restaurant.findById(req.params.id, 'name').lean();
        if (!doc) return res.status(404).json({ error: 'Restaurante no encontrado' });
        res.json({ name: doc.name });
    } catch (err) {
        res.status(500).json({ error: 'Error al obtener el nombre' });
    }
});

// Iniciar el servidor en el puerto 5000
app.listen(PORT, () => {
    console.log(`Servidor backend corriendo en http://localhost:${PORT}`);
});



//Singup
app.post('/register', async (req, res) => {
    try {
        const { email, password, role, name } = req.body;

        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({ error: 'El correo electrónico ya está registrado' });
        }

        // Cifrar la contraseña
        const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        // Crear un nuevo usuario
        const user = new User({
            email,
            password: hashedPassword,
            role,
            name
        });

        await user.save();
        res.status(201).json({ message: 'Usuario registrado correctamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error al registrar el usuario' });
    }
});

//Login
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        // Buscar el usuario
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Usuario no encontrado' });
        }
        // Comparar la contraseña
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Contraseña incorrecta' });
        }

        // Crear un JWT
        const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });

        res.json({
            token,
            user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role
            }
        });

    } catch (error) {
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});



// Middleware para verificar el JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Obtenemos el token del encabezado

    if (!token) {
        return res.status(403).json({ error: 'No se proporciona token' });
    }

    try {
        const decoded = jwt.verify(token, 'JWT_SECRET');
        req.user = decoded; // Guardamos la información del usuario decodificada
        next(); // Continuar con la siguiente función
    } catch (error) {
        res.status(401).json({ error: 'Token inválido o expirado' });
    }
};



const verifyRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'No tienes permisos suficientes' });
        }
        next();
    };
};

app.use('/admin', verifyToken, verifyRole('admin'));

app.get('/admin', (req, res) => {
    res.json({ message: 'Bienvenido, admin' });
});

app.get(
    '/inventary',
    verifyToken,            // 1) ¿Trae JWT válido?
    verifyRole('admin'),    // 2) ¿Es admin?
    async (req, res) => {
        try {
            const items = await Inventory.find();
            res.json(items);
        } catch (err) {
            res.status(500).json({ error: 'Error al obtener inventario' });
        }
    }
);

// Endpoints para el sistema de calificaciones (Rating)

// 1. Obtener todas las calificaciones
app.get('/ratings', async (req, res) => {
    try {
        const ratings = await Rating.find();
        res.json(ratings);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener las calificaciones' });
    }
});

// 2. Obtener calificaciones por producto
app.get('/products/:id/ratings', async (req, res) => {
    try {
        const productId = req.params.id;
        const ratings = await Rating.find({ product_id: productId });
        res.json(ratings);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener las calificaciones del producto' });
    }
});

// 3. Obtener una calificación específica
app.get('/ratings/:id', async (req, res) => {
    try {
        const ratingId = req.params.id;
        const rating = await Rating.findById(ratingId);
        
        if (!rating) {
            return res.status(404).json({ error: 'Calificación no encontrada' });
        }
        
        res.json(rating);
    } catch (error) {
        res.status(500).json({ error: 'Error al obtener la calificación' });
    }
});

// 4. Crear una nueva calificación
app.post('/products/:id/ratings', verifyToken, async (req, res) => {
    try {
        const { user_id, score, comment } = req.body;
        const product_id = req.params.id;
        
        // Validación básica
        if (!user_id || !score || score < 1 || score > 5) {
            return res.status(400).json({ error: 'Datos de calificación inválidos' });
        }
        
        // Verificar si el usuario ya calificó este producto
        const existingRating = await Rating.findOne({ product_id, user_id });
        if (existingRating) {
            return res.status(400).json({ error: 'El usuario ya ha calificado este producto' });
        }
        
        const newRating = new Rating({
            product_id,
            user_id,
            score,
            comment,
            date: new Date()
        });
        
        await newRating.save();
        
        // Actualizar la calificación promedio en el producto
        await updateProductAverageRating(product_id);
        
        res.status(201).json(newRating);
    } catch (error) {
        res.status(500).json({ error: 'Error al crear la calificación' });
    }
});

// 5. Actualizar una calificación existente
app.put('/ratings/:id', verifyToken, async (req, res) => {
    try {
        const ratingId = req.params.id;
        const { score, comment } = req.body;
        
        // Validación básica
        if (score && (score < 1 || score > 5)) {
            return res.status(400).json({ error: 'Puntuación inválida' });
        }
        
        const rating = await Rating.findById(ratingId);
        
        if (!rating) {
            return res.status(404).json({ error: 'Calificación no encontrada' });
        }
        
        // Actualizar solo los campos proporcionados
        if (score) rating.score = score;
        if (comment !== undefined) rating.comment = comment;
        rating.date = new Date(); // Actualizar fecha
        
        await rating.save();
        
        // Actualizar la calificación promedio en el producto
        await updateProductAverageRating(rating.product_id);
        
        res.json(rating);
    } catch (error) {
        res.status(500).json({ error: 'Error al actualizar la calificación' });
    }
});

// 6. Eliminar una calificación
app.delete('/ratings/:id', verifyToken, async (req, res) => {
    try {
        const ratingId = req.params.id;
        const rating = await Rating.findById(ratingId);
        
        if (!rating) {
            return res.status(404).json({ error: 'Calificación no encontrada' });
        }
        
        const productId = rating.product_id;
        
        await Rating.findByIdAndDelete(ratingId);
        
        // Actualizar la calificación promedio en el producto
        await updateProductAverageRating(productId);
        
        res.json({ message: 'Calificación eliminada correctamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error al eliminar la calificación' });
    }
});

// 7. Obtener el promedio de calificaciones de un producto
app.get('/products/:id/ratings/average', async (req, res) => {
    try {
        const productId = req.params.id;
        const result = await Rating.aggregate([
            { $match: { product_id: productId } },
            { $group: {
                _id: null,
                averageScore: { $avg: "$score" },
                totalRatings: { $sum: 1 }
            }}
        ]);
        
        if (result.length === 0) {
            return res.json({ averageScore: 0, totalRatings: 0 });
        }
        
        res.json({
            averageScore: parseFloat(result[0].averageScore.toFixed(1)),
            totalRatings: result[0].totalRatings
        });
    } catch (error) {
        res.status(500).json({ error: 'Error al calcular el promedio de calificaciones' });
    }
});

// Función auxiliar para actualizar la calificación promedio en el modelo de Producto
async function updateProductAverageRating(productId) {
    try {
        const result = await Rating.aggregate([
            { $match: { product_id: productId } },
            { $group: {
                _id: null,
                averageScore: { $avg: "$score" },
                totalRatings: { $sum: 1 }
            }}
        ]);
        
        let averageRating = 0;
        let totalRatings = 0;
        
        if (result.length > 0) {
            averageRating = result[0].averageScore;
            totalRatings = result[0].totalRatings;
        }
        
        // Actualizar el producto - Ten en cuenta que tu modelo Product tiene 'calification' en lugar de 'averageRating'
        await Product.findByIdAndUpdate(productId, {
            calification: parseFloat(averageRating.toFixed(1))
        });
    } catch (error) {
        console.error('Error al actualizar la calificación promedio del producto:', error);
    }
}
