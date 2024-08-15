# SegInf_T8
LGPD

--------CRIAR TABELA EM DATABASE-----------------------------------
DATABASE: seguro

CREATE TABLE consentimentos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    consentimento_comunicacoes BOOLEAN NOT NULL,
    consentimento_cookies BOOLEAN NOT NULL,
    data_consentimento TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-------------------------------------------------------------------

----------------------TESTE PREFERENCIAS---------------------------
http://localhost/LGPD/preferencias.php?email=usuario@example.com
-------------------------------------------------------------------
