// server.js - API Complète GCAFO Booking
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// Configuration PostgreSQL
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Token requis' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token invalide' });
        req.user = user;
        next();
    });
};

// Initialisation de la base de données
async function initDatabase() {
    try {
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
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.status(201).json({
            message: 'Utilisateur créé avec succès',
            token,
            user: { 
                id: newUser.id, 
                email: newUser.email, 
                full_name: newUser.full_name, 
                role: newUser.role,
                ville: newUser.ville,
                secteur: newUser.secteur
            }
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
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Connexion réussie',
            token,
            user: {
                id: user.id,
                email: user.email,
                full_name: user.full_name,
                role: user.role,
                is_verified: user.is_verified,
                is_certified: user.is_certified,
                ville: user.ville,
                secteur: user.secteur,
                profile_image: user.profile_image
            }
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
        
        res.json({
            prestataire: prestataireResult.rows[0],
            services: servicesResult.rows,
            avis: avisResult.rows
        });
        
    } catch (error) {
        console.error('Erreur get prestataire:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// PUT /api/prestataires/profile
app.put('/api/prestataires/profile', authenticateToken, async (req, res) => {
    try {
        const { metier, description, annees_experience, tarif_horaire, zone_intervention, adresse, portfolio, disponibilites } = req.body;
        
        const result = await pool.query(`
            UPDATE prestataire_profiles 
            SET metier = $1, description = $2, annees_experience = $3, tarif_horaire = $4, 
                zone_intervention = $5, adresse = $6, portfolio = $7, disponibilites = $8
            WHERE user_id = $9
            RETURNING *
        `, [metier, description, annees_experience, tarif_horaire, zone_intervention, adresse, portfolio, disponibilites, req.user.userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Profil non trouvé' });
        }
        
        res.json({ 
            message: 'Profil mis à jour avec succès',
            profile: result.rows[0]
        });
        
    } catch (error) {
        console.error('Erreur update profile:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== ROUTES SERVICES ====================

// POST /api/services
app.post('/api/services', authenticateToken, async (req, res) => {
    try {
        const { nom_service, description, prix, duree_estimee, categorie } = req.body;
        
        // Vérifier que l'utilisateur est un prestataire
        const userResult = await pool.query(
            'SELECT role FROM users WHERE id = $1',
            [req.user.userId]
        );
        
        if (userResult.rows[0].role !== 'prestataire') {
            return res.status(403).json({ error: 'Accès réservé aux prestataires' });
        }
        
        // Récupérer l'ID du profil prestataire
        const profileResult = await pool.query(
            'SELECT id FROM prestataire_profiles WHERE user_id = $1',
            [req.user.userId]
        );
        
        if (profileResult.rows.length === 0) {
            return res.status(404).json({ error: 'Profil prestataire non trouvé' });
        }
        
        const prestataireId = profileResult.rows[0].id;
        
        const result = await pool.query(`
            INSERT INTO services (prestataire_id, nom_service, description, prix, duree_estimee, categorie)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
        `, [prestataireId, nom_service, description, prix, duree_estimee, categorie]);
        
        res.status(201).json({
            message: 'Service créé avec succès',
            service: result.rows[0]
        });
        
    } catch (error) {
        console.error('Erreur create service:', error);
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

// PUT /api/bookings/:id/status
app.put('/api/bookings/:id/status', authenticateToken, async (req, res) => {
    try {
        const { statut } = req.body;
        
        const result = await pool.query(
            'UPDATE bookings SET statut = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2 RETURNING *',
            [statut, req.params.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Réservation non trouvée' });
        }
        
        res.json({ 
            message: 'Statut mis à jour avec succès',
            booking: result.rows[0]
        });
        
    } catch (error) {
        console.error('Erreur update booking status:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== ROUTES AVIS ====================

// POST /api/reviews
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { booking_id, note, commentaire } = req.body;
        
        // Vérifier que la réservation appartient au client et est terminée
        const bookingResult = await pool.query(
            'SELECT * FROM bookings WHERE id = $1 AND client_id = $2 AND statut = $3',
            [booking_id, req.user.userId, 'termine']
        );
        
        if (bookingResult.rows.length === 0) {
            return res.status(403).json({ error: 'Non autorisé ou réservation non terminée' });
        }
        
        // Vérifier si un avis existe déjà
        const existingReview = await pool.query(
            'SELECT id FROM reviews WHERE booking_id = $1',
            [booking_id]
        );
        
        if (existingReview.rows.length > 0) {
            return res.status(400).json({ error: 'Un avis existe déjà pour cette réservation' });
        }
        
        const result = await pool.query(`
            INSERT INTO reviews (booking_id, note, commentaire)
            VALUES ($1, $2, $3)
            RETURNING *
        `, [booking_id, note, commentaire]);
        
        // Mettre à jour la note moyenne du prestataire
        await pool.query(`
            UPDATE prestataire_profiles 
            SET note_moyenne = (
                SELECT AVG(r.note)::numeric(3,2) 
                FROM reviews r
                INNER JOIN bookings b ON r.booking_id = b.id
                WHERE b.prestataire_id = prestataire_profiles.id
            ),
            nombre_avis = (
                SELECT COUNT(*) 
                FROM reviews r
                INNER JOIN bookings b ON r.booking_id = b.id
                WHERE b.prestataire_id = prestataire_profiles.id
            )
            WHERE id = $1
        `, [bookingResult.rows[0].prestataire_id]);
        
        res.status(201).json({ 
            message: 'Avis ajouté avec succès',
            review: result.rows[0]
        });
        
    } catch (error) {
        console.error('Erreur create review:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== ROUTES MESSAGES ====================

// GET /api/messages/:booking_id
app.get('/api/messages/:booking_id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT m.*, u.full_name as expediteur_name, u.profile_image as expediteur_image
            FROM messages m
            INNER JOIN users u ON m.expediteur_id = u.id
            WHERE m.booking_id = $1
            ORDER BY m.created_at ASC
        `, [req.params.booking_id]);
        
        res.json({ messages: result.rows });
        
    } catch (error) {
        console.error('Erreur get messages:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// POST /api/messages
app.post('/api/messages', authenticateToken, async (req, res) => {
    try {
        const { booking_id, message } = req.body;
        
        const result = await pool.query(`
            INSERT INTO messages (booking_id, expediteur_id, message)
            VALUES ($1, $2, $3)
            RETURNING *
        `, [booking_id, req.user.userId, message]);
        
        res.status(201).json({
            message: 'Message envoyé avec succès',
            message_data: result.rows[0]
        });
        
    } catch (error) {
        console.error('Erreur send message:', error);
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

// ==================== DÉMARRAGE DU SERVEUR ====================

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    await initDatabase();
});

// Export pour les tests
module.exports = app;
