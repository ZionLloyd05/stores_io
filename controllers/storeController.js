const mongoose = require('mongoose')
const Store = mongoose.model('Store')
const multer = require('multer')
const jimp = require('jimp')
const uuid = require('uuid')



const multerOptions = {
    storage: multer.memoryStorage(),
    fileFilter(req, file, next) {
        const isPhoto = file.mimetype.startsWith('image/')
        if(isPhoto){
            next(null, true)
        } else {
            next({ message: 'That fileType isn\'t allowed!'}, false)
        }
    }
}

exports.homePage = (req, res) => {
    res.render('index', {title: 'Home'})
}

exports.addStore = (req, res) => {
    res.render('editStore', {title: 'Add Store'})
}

//this uploads into memory
exports.upload = multer(multerOptions).single('photo')

exports.resize = async (req, res, next) => {
    if(!req.file){
        return next()
    }
    const extension = req.file.mimetype.split('/')[1]
    req.body.photo = `${uuid.v4()}.${extension}`

    //now resize the photo
    const photo = await jimp.read(req.file.buffer)
    await photo.resize(800, jimp.AUTO)
    await photo.write(`./public/uploads/${req.body.photo}`)

    next()
}

exports.createStore = async (req, res) => {
    const store = await (new Store(req.body)).save()
    req.flash('success', `Successfully Created ${store.name}. 
    Care to leave a review ? `)
    res.redirect(`/stores/${store.slug}`)
}

exports.getStores = async (req, res) => {
    const stores = await Store.find()
    // console.log(stores)
    res.render('stores', { title: 'Stores', stores })
}

exports.editStore = async (req, res) => {
    // console.log(req.params)
    const store = await Store.findOne({ _id: req.params.id})
    res.render('editStore', {title: `Edit ${store.name}`, store })
}

exports.updateStore = async (req, res) => {
    const store = await Store.findOneAndUpdate({ _id: req.params.id }, req.body, {
        new: true, // return the new store instead of old
        runValidators: true
    }).exec()
    req.flash('success', `Successfully updated <strong>${store.name}</strong>. <a href="/stores/${store.slug}">View Store ->> </a>`)
    res.redirect(`/stores/${store._id}/edit`)
}

exports.getStoreBySlug = async (req, res, next) => {
    const store = await Store.findOne({ slug: req.params.slug})
    if(!store) return next()
    res.render('store', { title: store.name, store })
}

exports.getStoresByTag = async (req, res) => {
    const tag = req.params.tag
    const tagQuery = tag || { $exists: true }
    const tagsPromise = Store.getTagsList()
    const storesPromise = Store.find({ tags: tagQuery })
    const [tags, stores] = await Promise.all([tagsPromise, storesPromise])

    res.render('tag', {tags, stores, title: 'Tag', tag})
}