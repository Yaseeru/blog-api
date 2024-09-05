const express = require("express");
const logger = require('./server/config/logger');
const expressLayout = require("express-ejs-layouts");
const methoOverride = require('method-override')
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const ejs = require("ejs");
require("dotenv").config();

const connectDB = require("./server/config/db");
const isActiveRoute  = require('./server/helpers/routeHelpers')
const PORT = 3000 || process.env.PORT

// Connect to the database
connectDB();

const app = express();

app.use(expressLayout);
app.set("layout", "./layouts/main");
app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(methoOverride('_method'))

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUnitialized: true,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
    })
}));

app.use(express.static("public"));

app.locals.isActiveRoute = isActiveRoute;

app.use("/", require("./server/routes/main"));
app.use("/", require("./server/routes/admin"));
app.use("/", require("./server/routes/users"));



app.use((req, res, next) => {
    logger.info(`Incoming request: ${req.method} ${req.url}`);
    next();
  });


app.listen(PORT, () => {
    logger.info(`Server started on port 3000${PORT}`);
});