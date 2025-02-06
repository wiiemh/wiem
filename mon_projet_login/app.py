from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import json  # Ajouter l'importation du module JSON
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'
app.permanent_session_lifetime = timedelta(days=1)  # Session valable 1 jour

# Configuration de la base de données MySQL
db_config = {
    'host': 'localhost',
    'user': 'flask_user',
    'password': 'Wiem123@',
    'database': 'flask_login'
}

# Fonction pour se connecter à la base de données
def get_db_connection():
    return mysql.connector.connect(**db_config)

@app.before_request
def make_session_permanent():
    # Étend la durée de vie de la session à chaque requête
    session.permanent = True

# Route de la page d'accueil
@app.route('/')
def home():
    # Affiche la page d'accueil avec des options pour se connecter ou s'inscrire
    return render_template('index.html')

# Route pour le processus de connexion
@app.route('/login', methods=['POST'])
def login():
    # Récupération des données du formulaire
    email = request.form.get('email')
    password = request.form.get('password')

    # Vérification des champs obligatoires
    if not email or not password:
        flash('Veuillez remplir tous les champs', 'error')
        return redirect(url_for('home'))

    # Vérifie si les informations d'identification sont correctes
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
    user = cursor.fetchone()

    # Vérification du mot de passe
    if user and check_password_hash(user['password'], password):
        # Enregistre les informations de l'utilisateur dans la session
        session['user_id'] = user['id']
        session['username'] = user['username']

    # Interpréter la colonne `permissions` comme un tableau JSON
    permissions = json.loads(user['permissions']) if user['permissions'] else []

    # Affichez le contenu des permissions pour vérifier
    print(permissions)  # Ajoutez cette ligne ici pour voir les permissions

    # Assigner un rôle basé sur les permissions
    if 'super_admin' in permissions:
        session['role'] = 'Super Admin'
    elif user['is_admin']:
        session['role'] = 'Admin'
    else:
        session['role'] = 'Utilisateur'

    # Enregistre la connexion de l'utilisateur
    cursor.execute("INSERT INTO logins (user_id) VALUES (%s)", (user['id'],))
    conn.commit()

    cursor.close()
    conn.close()

    session.modified = True
    flash('Connexion réussie!', 'success')

    # Redirige en fonction du rôle de l'utilisateur
    if session['role'] in ['Admin', 'Super Admin']:
        return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))

    # Si l'authentification échoue
    cursor.close()
    conn.close()
    
    flash('Email ou mot de passe incorrect', 'error')
    return redirect(url_for('home'))

# Route pour l'inscription d'un nouvel utilisateur
@app.route('/signup', methods=['POST'])
def signup():
    # Récupération des données du formulaire
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    # Vérification des champs obligatoires
    if not name or not email or not password:
        flash('Veuillez remplir tous les champs', 'error')
        return redirect(url_for('home'))

    # Hachage du mot de passe avant de l'enregistrer
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Insère l'utilisateur dans la base de données avec un rôle utilisateur par défaut
        cursor.execute(
            'INSERT INTO users (username, email, password, is_admin, permissions) VALUES (%s, %s, %s, %s, %s)',
            (name, email, hashed_password, False, json.dumps([]))  # Par défaut, permissions vide (utilisateur normal)
        )
        conn.commit()
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
    except mysql.connector.IntegrityError:
        # Gère les doublons d'email
        flash('Cet email est déjà utilisé', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('home'))

# Route pour afficher le tableau de bord administrateur
@app.route('/admin/dashboard')
def admin_dashboard():
    # Vérifie si l'utilisateur est connecté et a les droits d'administrateur
    if 'user_id' not in session or session.get('role') not in ['Admin', 'Super Admin']:
        flash('Accès refusé : vous devez être administrateur.', 'error')
        return redirect(url_for('home'))

    # Récupère les utilisateurs de la base de données pour les afficher
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT id, username, email, is_admin, permissions FROM users')
    users = cursor.fetchall()
    cursor.close()
    conn.close()

                # Assigne un rôle à chaque utilisateur
    for user in users:
        # Assigne le rôle de 'Super Admin' si l'utilisateur a la permission 'super_admin'
        if 'super_admin' in json.loads(user.get('permissions', '[]')):
            user['role'] = 'Super Admin'
        elif user['is_admin']:
            user['role'] = 'Admin'
        else:
            user['role'] = 'Utilisateur'

    return render_template('admin_dashboard.html', users=users)

@app.route('/user/dashboard')
def user_dashboard():
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour accéder à cette page.', 'error')
        return redirect(url_for('home'))

    return render_template('user_dashboard.html', username=session.get('username'))


# Route pour afficher le tableau des rôles (accessible à tous les utilisateurs connectés)
@app.route('/admin/roles')
def admin_roles():
    # Vérifie si l'utilisateur est connecté
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour accéder à cette page.', 'error')
        return redirect(url_for('home'))

    # Récupère les utilisateurs de la base de données
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT id, username, email, is_admin, permissions FROM users')
    users = cursor.fetchall()
    cursor.close()
    conn.close()

    # Assigne un rôle à chaque utilisateur
    for user in users:
        # Assigne le rôle de 'Super Admin' si l'utilisateur a la permission 'super_admin'
        if 'super_admin' in json.loads(user.get('permissions', '[]')):
            user['role'] = 'Super Admin'
        elif user['is_admin']:
            user['role'] = 'Admin'
        else:
            user['role'] = 'Utilisateur'

    # Affiche le tableau des utilisateurs avec leurs rôles
    return render_template('admin_roles.html', users=users)

# Route pour modifier un utilisateur (réservée aux administrateurs)
@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # Vérifie si l'utilisateur est connecté et a les droits d'administrateur
    if 'user_id' not in session or session.get('role') not in ['Admin', 'Super Admin']:
        flash('Accès refusé : vous devez être administrateur.', 'error')
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT id, username, email, is_admin, permissions FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()

    if not user:
        flash("Utilisateur introuvable", "error")
        return redirect(url_for('admin_dashboard'))

    # Empêche les admins simples de modifier les autres admins
    if session.get('role') != 'Super Admin' and user['is_admin']:
        flash("Vous n'avez pas les permissions pour modifier un administrateur", "error")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Met à jour les informations de l'utilisateur
        username = request.form.get('username')
        email = request.form.get('email')
        is_admin = request.form.get('is_admin') == 'on'
        permissions = request.form.get('permissions', '')

        cursor.execute(
            'UPDATE users SET username = %s, email = %s, is_admin = %s, permissions = %s WHERE id = %s',
            (username, email, is_admin, json.dumps(permissions.split(',')), user_id)
        )
        conn.commit()
        flash("Utilisateur mis à jour avec succès", "success")
        return redirect(url_for('admin_dashboard'))

    cursor.close()
    conn.close()
    return render_template('edit_user.html', user=user)

# Route pour supprimer un utilisateur (réservée aux administrateurs)
@app.route('/admin/delete_user/<int:user_id>', methods=['POST', 'GET'])
def delete_user(user_id):
    # Vérifie si l'utilisateur est connecté et a les droits d'administrateur
    if 'user_id' not in session or session.get('role') not in ['Admin', 'Super Admin']:
        flash('Accès refusé : vous devez être administrateur.', 'error')
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Supprime l'utilisateur de la base de données
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        flash('Utilisateur supprimé avec succès.', 'success')
    except Exception as e:
        flash(f"Erreur lors de la suppression : {e}", 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Veuillez vous connecter pour accéder au tableau de bord.', 'error')
        return redirect(url_for('home'))

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Récupération du nombre d'utilisateurs
    cursor.execute('SELECT COUNT(*) AS user_count FROM users')
    user_count = cursor.fetchone()['user_count']

    # Exemple : récupération des connexions (ajustez la requête selon vos besoins)
    cursor.execute('SELECT COUNT(*) AS login_count FROM logins')  # Supposez que vous avez une table `logins`
    login_count = cursor.fetchone()['login_count']

    cursor.close()
    conn.close()

    user = {
        'username': session.get('username', 'Utilisateur inconnu'),
    }

    return render_template('dashboard.html', user=user, user_count=user_count, login_count=login_count)

@app.route('/logout')
def logout():
    # Supprimer toutes les données de la session
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('home'))  # Redirige vers la page d'accueil après déconnexion

# Exécute l'application Flask
if __name__ == '__main__':
    app.run(debug=True)
