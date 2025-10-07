// server.js - API Complète GCAFO Booking
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Configuration PostgreSQL pour Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/gcafo_booking',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Token requis' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = user;
    next();
  });
};

// Initialisation de la base de données
async function initDatabase() {
  try {
    console.log('🔄 Initialisation de la base de données...');
    
    // Table users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) CHECK (role IN ('client', 'prestataire')) NOT NULL,
        full_name VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        profile_image VARCHAR(500),
        is_verified BOOLEAN DEFAULT FALSE,
        is_certified BOOLEAN DEFAULT FALSE,
        ville VARCHAR(100),
        secteur VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table prestataire_profiles
    await pool.query(`
      CREATE TABLE IF NOT EXISTS prestataire_profiles (
        id SERIAL PRIMARY KEY,
        user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        metier VARCHAR(255) NOT NULL,
        description TEXT,
        annees_experience INTEGER,
        tarif_horaire DECIMAL(10,2),
        zone_intervention VARCHAR(255),
        adresse TEXT,
        portfolio JSONB,
        disponibilites JSONB,
        note_moyenne DECIMAL(3,2) DEFAULT 0.00,
        nombre_avis INTEGER DEFAULT 0
      )
    `);

    // Table services
    await pool.query(`
      CREATE TABLE IF NOT EXISTS services (
        id SERIAL PRIMARY KEY,
        prestataire_id INTEGER NOT NULL REFERENCES prestataire_profiles(id) ON DELETE CASCADE,
        nom_service VARCHAR(255) NOT NULL,
        description TEXT,
        prix DECIMAL(10,2),
        duree_estimee INTEGER,
        categorie VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table bookings
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        client_id INTEGER NOT NULL REFERENCES users(id),
        prestataire_id INTEGER NOT NULL REFERENCES prestataire_profiles(id),
        service_id INTEGER NOT NULL REFERENCES services(id),
        date_reservation TIMESTAMP NOT NULL,
        statut VARCHAR(20) CHECK (statut IN ('en_attente', 'confirme', 'annule', 'termine')) DEFAULT 'en_attente',
        adresse_prestation TEXT,
        prix_final DECIMAL(10,2),
        notes_client TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table reviews
    await pool.query(`
      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        booking_id INTEGER UNIQUE NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
        note INTEGER CHECK (note >= 1 AND note <= 5),
        commentaire TEXT,
        photos_review JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Table messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        booking_id INTEGER NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
        expediteur_id INTEGER NOT NULL REFERENCES users(id),
        message TEXT NOT NULL,
        lu BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('✅ Base de données initialisée avec succès');
  } catch (error) {
    console.error('❌ Erreur initialisation base de données:', error);
  }
}

// ==================== ROUTES AUTHENTIFICATION ====================

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, full_name, phone, role, ville, secteur } = req.body;
    
    // Vérifier si l'email existe déjà
    const existing = await pool.query(
      'SELECT id FROM users WHERE email = $1', 
      [email]
    );
    
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email déjà utilisé' });
    }
    
    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Créer l'utilisateur
    const result = await pool.query(
      'INSERT INTO users (email, password, full_name, phone, role, ville, secteur) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [email, hashedPassword, full_name, phone, role, ville, secteur]
    );
    
    const newUser = result.rows[0];
    
    // Créer le profil prestataire si nécessaire
    if (role === 'prestataire') {
      await pool.query(
        'INSERT INTO prestataire_profiles (user_id, metier) VALUES ($1, $2)',
        [newUser.id, 'Général']
      );
    }
    
    // Générer le token JWT
    const token = jwt.sign(
      { userId: newUser.id, email, role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );
    
    // Retirer le mot de passe de la réponse
    const { password: _, ...userWithoutPassword } = newUser;
    
    res.status(201).json({
      message: 'Utilisateur créé avec succès',
      token,
      user: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Erreur register:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1', 
      [email]
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    
    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }
    
    const token = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'fallback_secret',
      { expiresIn: '24h' }
    );
    
    // Retirer le mot de passe de la réponse
    const { password: _, ...userWithoutPassword } = user;
    
    res.json({
      message: 'Connexion réussie',
      token,
      user: userWithoutPassword
    });
    
  } catch (error) {
    console.error('Erreur login:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES PRESTATAIRES ====================

// GET /api/prestataires
app.get('/api/prestataires', async (req, res) => {
  try {
    const { ville, metier, page = 1, limit = 10 } = req.query;
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT 
        u.id, u.full_name, u.profile_image, u.is_verified, u.is_certified,
        p.metier, p.description, p.note_moyenne, p.nombre_avis, p.zone_intervention,
        p.tarif_horaire, p.annees_experience, u.ville, u.secteur
      FROM users u
      INNER JOIN prestataire_profiles p ON u.id = p.user_id
      WHERE u.role = 'prestataire'
    `;
    let params = [];
    let paramCount = 0;
    
    if (ville) {
      paramCount++;
      query += ` AND u.ville ILIKE $${paramCount}`;
      params.push(`%${ville}%`);
    }
    
    if (metier) {
      paramCount++;
      query += ` AND p.metier ILIKE $${paramCount}`;
      params.push(`%${metier}%`);
    }
    
    paramCount++;
    query += ` ORDER BY p.note_moyenne DESC LIMIT $${paramCount}`;
    params.push(parseInt(limit));
    
    paramCount++;
    query += ` OFFSET $${paramCount}`;
    params.push(offset);
    
    const result = await pool.query(query, params);
    
    res.json({
      prestataires: result.rows,
      pagination: { page: parseInt(page), limit: parseInt(limit) }
    });
    
  } catch (error) {
    console.error('Erreur get prestataires:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/prestataires/:id
app.get('/api/prestataires/:id', async (req, res) => {
  try {
    const prestataireResult = await pool.query(`
      SELECT 
        u.*, p.*
      FROM users u
      INNER JOIN prestataire_profiles p ON u.id = p.user_id
      WHERE u.id = $1 AND u.role = 'prestataire'
    `, [req.params.id]);
    
    if (prestataireResult.rows.length === 0) {
      return res.status(404).json({ error: 'Prestataire non trouvé' });
    }
    
    // Récupérer les services
    const servicesResult = await pool.query(`
      SELECT * FROM services 
      WHERE prestataire_id = $1
      ORDER BY created_at DESC
    `, [prestataireResult.rows[0].id]);
    
    // Récupérer les avis
    const avisResult = await pool.query(`
      SELECT r.*, u.full_name as client_name, u.profile_image as client_image
      FROM reviews r
      INNER JOIN bookings b ON r.booking_id = b.id
      INNER JOIN users u ON b.client_id = u.id
      WHERE b.prestataire_id = $1
      ORDER BY r.created_at DESC
      LIMIT 20
    `, [prestataireResult.rows[0].id]);
    
    const { password: _, ...prestataireWithoutPassword } = prestataireResult.rows[0];
    
    res.json({
      prestataire: prestataireWithoutPassword,
      services: servicesResult.rows,
      avis: avisResult.rows
    });
    
  } catch (error) {
    console.error('Erreur get prestataire:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES SERVICES ====================

// GET /api/services
app.get('/api/services', async (req, res) => {
  try {
    const { prestataire_id } = req.query;
    
    let query = `
      SELECT s.*, u.full_name as prestataire_name, u.profile_image as prestataire_image
      FROM services s
      INNER JOIN prestataire_profiles p ON s.prestataire_id = p.id
      INNER JOIN users u ON p.user_id = u.id
      WHERE 1=1
    `;
    let params = [];
    let paramCount = 0;
    
    if (prestataire_id) {
      paramCount++;
      query += ` AND s.prestataire_id = $${paramCount}`;
      params.push(prestataire_id);
    }
    
    query += ` ORDER BY s.created_at DESC`;
    
    const result = await pool.query(query, params);
    
    res.json({ services: result.rows });
    
  } catch (error) {
    console.error('Erreur get services:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES RÉSERVATIONS ====================

// POST /api/bookings
app.post('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const { prestataire_id, service_id, date_reservation, adresse_prestation, notes } = req.body;
    
    const result = await pool.query(`
      INSERT INTO bookings 
      (client_id, prestataire_id, service_id, date_reservation, adresse_prestation, notes_client)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [req.user.userId, prestataire_id, service_id, date_reservation, adresse_prestation, notes]);
    
    res.status(201).json({
      message: 'Réservation créée avec succès',
      booking: result.rows[0]
    });
    
  } catch (error) {
    console.error('Erreur create booking:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/bookings
app.get('/api/bookings', authenticateToken, async (req, res) => {
  try {
    const { statut } = req.query;
    
    let query = `
      SELECT 
        b.*,
        u_presta.full_name as prestataire_name,
        u_presta.profile_image as prestataire_image,
        u_client.full_name as client_name,
        s.nom_service,
        s.prix as service_prix
      FROM bookings b
      INNER JOIN users u_presta ON b.prestataire_id = u_presta.id
      INNER JOIN users u_client ON b.client_id = u_client.id
      INNER JOIN services s ON b.service_id = s.id
      WHERE (b.client_id = $1 OR b.prestataire_id = $1)
    `;
    let params = [req.user.userId];
    
    if (statut) {
      query += ` AND b.statut = $2`;
      params.push(statut);
    }
    
    query += ` ORDER BY b.created_at DESC`;
    
    const result = await pool.query(query, params);
    
    res.json({ bookings: result.rows });
    
  } catch (error) {
    console.error('Erreur get bookings:', error);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// Route de test
app.get('/', (req, res) => {
  res.json({ 
    message: '🚀 API GCAFO Booking est en ligne!',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth/register, /api/auth/login',
      prestataires: '/api/prestataires',
      bookings: '/api/bookings',
      services: '/api/services'
    }
  });
});

// Gestion des routes non trouvées
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route non trouvée' });
});

// Gestion des erreurs
app.use((error, req, res, next) => {
  console.error('Erreur:', error);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

// Démarrage du serveur
const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
  console.log(`🚀 Serveur démarré sur le port ${PORT}`);
  console.log(`📍 Environnement: ${process.env.NODE_ENV || 'development'}`);
  await initDatabase();
});

module.exports = app;
