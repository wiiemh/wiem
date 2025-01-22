from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete'  # Clé secrète pour les messages flash

# Simuler une base de données en mémoire
users = {}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    # Vérifier si l'utilisateur existe et si le mot de passe correspond
    if email in users and users[email] == password:
        flash('Connexion réussie!', 'success')
        return redirect(url_for('home'))
    else:
        flash('Email ou mot de passe incorrect', 'error')
        return redirect(url_for('home'))

@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')

    # Vérifier si l'email est déjà utilisé
    if email in users:
        flash('Cet email est déjà utilisé', 'error')
    else:
        users[email] = password
        flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')

    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)