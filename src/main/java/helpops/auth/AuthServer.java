package helpops.auth;

import helpops.interfaces.RMIAuthService;
import helpops.model.Token;
import helpops.utils.DatabaseManager;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

// Serveur d'Authentification : Gestion de la sécurité, des sessions et des rôles
public class AuthServer extends UnicastRemoteObject implements RMIAuthService {
    // Sessions actives
    private Map<String, Token> tokensActifs = new HashMap<>();

    public AuthServer() throws RemoteException {
        super();
        System.out.println("[AUTH] Serveur d'authentification prêt ... ");
    }

    @Override
    public Token connecter(String login, String mdpHache) throws RemoteException {
        String sql = "SELECT user_uuid, role FROM users WHERE login = ? AND password_hash = ?";
        //connexion a la bd
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, login);
            pstmt.setString(2, mdpHache);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                UUID uuid = (UUID) rs.getObject("user_uuid");
                String role = rs.getString("role");
                Token t = new Token(UUID.randomUUID().toString(), login, uuid, role);
                tokensActifs.put(t.getValeur(), t);
                System.out.println("[AUTH] Connexion réussie : " + login + " (" + role + ")");
                return t;
            }} catch (SQLException e) {
            e.printStackTrace();}
        return null;}

    @Override
    public boolean changerRole(String tokenAgent, UUID utilisateurAChanger, String nouveauRole) throws RemoteException {
        String roleDemandeur = getRoleDepuisToken(tokenAgent);
        if (!"AGENT".equalsIgnoreCase(roleDemandeur)) {
            throw new RemoteException("Seul un agent peut modifier les privilèges.");}
        //Mise à jour en base de données
        String sql = "UPDATE users SET role = ? WHERE user_uuid = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, nouveauRole.toUpperCase());
            pstmt.setObject(2, utilisateurAChanger);
            return pstmt.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;}}

    @Override
    public boolean inscrire(String login, String mdpHache) throws RemoteException {
        String sql = "INSERT INTO users (user_uuid, login, password_hash, role) VALUES (?, ?, ?, ?)";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setObject(1, UUID.randomUUID());
            pstmt.setString(2, login);
            pstmt.setString(3, mdpHache);
            pstmt.setString(4, "UTILISATEUR");
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                System.err.println("[AUTH] Login déjà pris : " + login);
            } else {
                System.err.println("[AUTH] Erreur critique BDD : " + e.getMessage());}
            return false;}}

    @Override
    public UUID getUuidDepuisToken(String tokenValeur) throws RemoteException {
        Token t = tokensActifs.get(tokenValeur);
        if (t != null && t.estValide()) {
            return t.getUserUuid();}
        return null;}

    @Override
    public String getRoleDepuisToken(String tokenValeur) throws RemoteException {
        Token t = tokensActifs.get(tokenValeur);
        if (t != null && t.estValide()) {
            return t.getRole();}
        return null;}

    @Override
    public boolean verifierToken(String tokenValeur) throws RemoteException {
        Token t = tokensActifs.get(tokenValeur);
        if (t == null || !t.estValide()) {
            if (t != null) tokensActifs.remove(tokenValeur);
            return false;}
        return true;}

    @Override
    public String ping() throws RemoteException {
        return "AuthServer OK";
    }

    public static void main(String[] args) {
        try {
            Registry registry = LocateRegistry.createRegistry(1099);
            AuthServer auth = new AuthServer();
            registry.rebind("AuthService", auth);
            System.out.println("[AUTH] Ecoute sur le port 1099");
        } catch (Exception e) {
            e.printStackTrace();}}

}