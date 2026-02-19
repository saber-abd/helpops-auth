package helpops.auth;

import helpops.interfaces.IAuthService;
import helpops.model.Token;
import helpops.model.User;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;

public class AuthServer extends UnicastRemoteObject implements IAuthService {
    private static final String FICHIER_USERS = "users.txt";
    private Map<String, User> utilisateurs = new HashMap<>();
    private Map<String, Token> tokensActifs = new HashMap<>(); // tokenValeur -> Token (session en memoire, reinitialisee au redemarrage)

    public AuthServer() throws RemoteException {
        super();
        chargerUtilisateurs();
        if (utilisateurs.isEmpty()) {
            inscrire("alice",   "pass123");
            inscrire("bob",     "pass456");
            inscrire("charlie", "pass789");
            System.out.println("[AUTH] Comptes de test crees : alice, bob, charlie");
        }
        System.out.println("[AUTH] " + utilisateurs.size() + " utilisateur(s) charge(s).");
    }

    // Methodes RMI (definies dans IAuthService)
    @Override
    public Token connecter(String login, String motDePasse) throws RemoteException {
        User user = utilisateurs.get(login);
        if (user == null) {
            System.out.println("[AUTH] Login inconnu : " + login);
            return null;
        }
        if (!user.getMotDePasseHash().equals(hacher(motDePasse))) {
            System.out.println("[AUTH] Mauvais mot de passe pour : " + login);
            return null;
        }
        Token token = new Token(login);
        tokensActifs.put(token.getValeur(), token);
        System.out.println("[AUTH] Connexion OK : " + login);
        return token;
    }

    @Override
    public boolean inscrire(String login, String motDePasse) throws RemoteException {
        if (login == null || login.isBlank() || motDePasse == null || motDePasse.isBlank()) {
            return false;
        }
        if (utilisateurs.containsKey(login)) {
            System.out.println("[AUTH] Login deja utilise : " + login);
            return false;
        }
        utilisateurs.put(login, new User(login, hacher(motDePasse), "UTILISATEUR"));
        sauvegarderUtilisateurs();
        System.out.println("[AUTH] Nouvel utilisateur inscrit : " + login);
        return true;
    }

    @Override
    public boolean verifierToken(String tokenValeur) throws RemoteException {
        Token t = tokensActifs.get(tokenValeur);
        if (t == null || !t.estValide()) {
            tokensActifs.remove(tokenValeur);
            return false;
        }
        return true;
    }

    @Override
    public String getLoginDepuisToken(String tokenValeur) throws RemoteException {
        if (!verifierToken(tokenValeur)) return null;
        return tokensActifs.get(tokenValeur).getLogin();
    }

    @Override
    public String ping() throws RemoteException {
        return "AuthServer OK";
    }

    private void chargerUtilisateurs() {
        File f = new File(FICHIER_USERS);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(f, StandardCharsets.UTF_8))) {
            String ligne;
            while ((ligne = br.readLine()) != null) {
                ligne = ligne.trim();
                if (ligne.isEmpty()) continue;
                String[] parts = ligne.split(":");
                if (parts.length == 3) {
                    utilisateurs.put(parts[0], new User(parts[0], parts[1], parts[2]));
                }
            }
            System.out.println("[AUTH] Fichier users.txt lu.");
        } catch (Exception e) {
            System.err.println("[AUTH] Erreur lecture users.txt : " + e.getMessage());
        }
    }

    private void sauvegarderUtilisateurs() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(FICHIER_USERS, StandardCharsets.UTF_8))) {
            for (User u : utilisateurs.values()) {
                pw.println(u.getLogin() + ":" + u.getMotDePasseHash() + ":" + u.getRole());
            }
        } catch (Exception e) {
            System.err.println("[AUTH] Erreur ecriture users.txt : " + e.getMessage());
        }
    }

    private String hacher(String motDePasse) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(motDePasse.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("Erreur de hachage SHA-256", e);
        }
    }

    public static void main(String[] args) {
        try {
            System.setProperty("file.encoding", "UTF-8");
            // Creer le Registry RMI sur le port 2000
            Registry registry = LocateRegistry.createRegistry(2000);
            System.out.println("[AUTH] Registry RMI cree sur le port 2000");

            AuthServer auth = new AuthServer();
            registry.rebind("AuthService", auth);

            System.out.println("[AUTH] Service 'AuthService' enregistre. En attente de connexions...");
        } catch (Exception e) {
            System.err.println("[AUTH] Erreur demarrage : " + e.getMessage());
            e.printStackTrace();
        }
    }
}
