#!/usr/bin/env python
# coding: utf-8

# In[1]:


#create a mixed log file with 10,000 entries from multiple sources
import random

DESIRED_COUNT = 10000

# Dateien lesen
files = [
    'data/loghub_2k/Linux/Linux_2k.log',
    'data/loghub_2k/Apache/Apache_2k.log',
    'data/loghub_2k/OpenSSH/OpenSSH_2k.log',
]

all_lines = []
for filepath in files:
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        all_lines.extend(lines)


# Wenn zu wenige Logs vorhanden sind, zufällig duplizieren
if len(all_lines) < DESIRED_COUNT:
    missing_count = DESIRED_COUNT - len(all_lines)

    # Zufällige Zeilen aus den vorhandenen Logs auswählen und hinzufügen
    random.seed(42)  # Für Reproduzierbarkeit
    added_logs = random.choices(all_lines, k=missing_count)
    all_lines.extend(added_logs)

elif len(all_lines) > DESIRED_COUNT:
    random.seed(42)  # Für Reproduzierbarkeit
    random.shuffle(all_lines)
    all_lines = all_lines[:DESIRED_COUNT]

# Mischen
random.seed(42)  # Für Reproduzierbarkeit
random.shuffle(all_lines)

output_path = 'Mixed_10k.log'
with open(output_path, 'w', encoding='utf-8') as f:
    for line in all_lines:
        f.write(line)
        if not line.endswith('\n'):
            f.write('\n')


# In[2]:


# Label the mixed log file - Labels direkt aus DBSCAN Cluster übernehmen
import pandas as pd
from hashlib import sha256

# Logs einlesen
with open('./Mixed_10k.log', 'r', encoding='utf-8') as f:
    logs = f.readlines()

df_labeled = pd.DataFrame()
df_labeled['log'] = logs
df_labeled['cluster_id'] = -20
#df_labeled['hash'] = df_labeled['log'].apply(lambda x: sha256(x.encode('utf-8')).hexdigest())


df_labeled.loc[df_labeled['log'].str.contains("getpeername (ftpd): Transport endpoint is not connected", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 25
df_labeled.loc[df_labeled['log'].str.contains("combo .* authentication failure; logname= uid=", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 24
df_labeled.loc[df_labeled['log'].str.contains("LabSZ .* authentication failure; logname= uid=", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 23
df_labeled.loc[df_labeled['log'].str.contains("device node", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 22
df_labeled.loc[df_labeled['log'].str.contains("notify question section contains no SOA", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 21
df_labeled.loc[df_labeled['log'].str.contains("combo ftpd\[.*\]: connection from", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 19
df_labeled.loc[df_labeled['log'].str.contains("combo logrotate: ALERT exited abnormally with", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 18
df_labeled.loc[df_labeled['log'].str.contains("Kerberos authentication failed", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 17
df_labeled.loc[df_labeled['log'].str.contains("jk2_init()", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 16
df_labeled.loc[df_labeled['log'].str.contains("mod_jk child", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 15
df_labeled.loc[df_labeled['log'].str.contains("workerEnv.init()", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 14
df_labeled.loc[df_labeled['log'].str.contains("Bye Bye", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 13
df_labeled.loc[df_labeled['log'].str.contains("Failed password for root", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 12
df_labeled.loc[df_labeled['log'].str.contains("PAM service(sshd)", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 11
df_labeled.loc[df_labeled['log'].str.contains("combo .* check pass; user unknown", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 10
df_labeled.loc[df_labeled['log'].str.contains("LabSZ .* check pass; user unknown", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 9
df_labeled.loc[df_labeled['log'].str.contains("input_userauth_request: invalid user", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 8
df_labeled.loc[df_labeled['log'].str.contains("reverse mapping checking getaddrinfo", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 7
df_labeled.loc[df_labeled['log'].str.contains("Failed password for ftp", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 6
df_labeled.loc[df_labeled['log'].str.contains("Failed password for invalid user", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 5
df_labeled.loc[df_labeled['log'].str.contains("combo kernel", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 4
df_labeled.loc[df_labeled['log'].str.contains("combo su(pam_unix)", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 3
df_labeled.loc[df_labeled['log'].str.contains("combo sshd(pam_unix)", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 2
df_labeled.loc[df_labeled['log'].str.contains("LabSZ sshd\[\d*\]", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 1
df_labeled.loc[df_labeled['log'].str.contains("Directory index forbidden by rule", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = 0
df_labeled.loc[df_labeled['log'].str.contains("combo klogind\[\d*\]: Kerberos authentication failed", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -1
df_labeled.loc[df_labeled['log'].str.contains("combo klogind\[\d*\]: Authentication failed from", case=False, na=False, regex=True) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -2
df_labeled.loc[df_labeled['log'].str.contains("combo cups:", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -3
df_labeled.loc[df_labeled['log'].str.contains("combo bluetooth:", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -4
df_labeled.loc[df_labeled['log'].str.contains("combo syslogd", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -5
df_labeled.loc[df_labeled['log'].str.contains("combo network", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -6
df_labeled.loc[df_labeled['log'].str.contains("combo syslog", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -7
df_labeled.loc[df_labeled['log'].str.contains("combo sdpd", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -8
df_labeled.loc[df_labeled['log'].str.contains("combo ftpd", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -9
df_labeled.loc[df_labeled['log'].str.contains("combo hcid", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -10
df_labeled.loc[df_labeled['log'].str.contains("combo xinetd", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -11
df_labeled.loc[df_labeled['log'].str.contains("combo gpm", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -12
df_labeled.loc[df_labeled['log'].str.contains("combo login", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -13
df_labeled.loc[df_labeled['log'].str.contains("combo nfslock", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -14
df_labeled.loc[df_labeled['log'].str.contains("combo random", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -15
df_labeled.loc[df_labeled['log'].str.contains("combo gdm-binary", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -16
df_labeled.loc[df_labeled['log'].str.contains("combo portmap", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -17
df_labeled.loc[df_labeled['log'].str.contains("combo rpcidmapd", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -18
df_labeled.loc[df_labeled['log'].str.contains("combo rc", case=False, na=False, regex=False) & (df_labeled['cluster_id'] == -20), 'cluster_id'] = -19
df_labeled.to_csv('./Mixed_10k_labeled.log', index=False)




# In[3]:


from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

with open('Mixed_10k.log', 'r', encoding='utf-8', errors='ignore') as f:
    log_lines = [line.strip() for line in f.readlines() if line.strip()]

# TfidfVectorizer initialisieren und vektorisieren
vectorizer = TfidfVectorizer(max_features=1000, min_df=2, max_df=0.95)
X_tfidf = vectorizer.fit_transform(log_lines)

# Dimensionsreduzierung mit TruncatedSVD
n_components = 50  # Anzahl der Komponenten für die Dimensionsreduzierung
svd = TruncatedSVD(n_components=n_components, random_state=42)
X_reduced = svd.fit_transform(X_tfidf)

print(f"Originale Dimension: {X_tfidf.shape}")
print(f"Reduzierte Dimension: {X_reduced.shape}")
print(f"Erklärte Varianz: {svd.explained_variance_ratio_.sum():.4f}")
print(f"Anzahl der Komponenten: {n_components}")



# In[4]:


# ==========================================
# K-Means Parametersuche: Elbow (Knee) + Silhouette
# Bestimmt k datengetrieben: Knee in der Inertia-Kurve + Silhouette-Maximum
# ==========================================
try:
    from kneed import KneeLocator, find_shape
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "kneed"])
    from kneed import KneeLocator

from sklearn.cluster import KMeans
from sklearn.decomposition import TruncatedSVD
from sklearn.metrics import silhouette_score
import numpy as np
import matplotlib.pyplot as plt

K = range(2, 40)
KMEANS_RANDOM_STATE = 42

# Dimensionsreduktion (konsistent mit Implementierung in Zelle 9)
svd = TruncatedSVD(n_components=100, random_state=KMEANS_RANDOM_STATE)
X_reduced = svd.fit_transform(X_tfidf)

explained_variance = svd.explained_variance_ratio_.sum()
print(f"Erklärte Varianz: {explained_variance:.2%}")

inertias = []
silhouette_scores = []

for k in K:
    km = KMeans(n_clusters=k, random_state=KMEANS_RANDOM_STATE)
    labels = km.fit_predict(X_reduced)
    inertias.append(km.inertia_)
    silhouette_scores.append(
        silhouette_score(X_reduced, labels, sample_size=2000, random_state=KMEANS_RANDOM_STATE)
    )

k_list = list(K)


detected_direction, detected_curve = find_shape(np.array(k_list), np.array(inertias))
print(f"find_shape() erkennt: curve='{detected_curve}', direction='{detected_direction}'")

# Knee in der Inertia(WCSS)-Kurve (Elbow)
knee = KneeLocator(k_list, inertias, curve="convex", direction="decreasing")
k_elbow = knee.knee

# Optimales k aus Silhouette-Score
k_silhouette = k_list[int(np.argmax(silhouette_scores))]

print(f"Vorgeschlagenes k (Elbow/Knee):     {k_elbow}")
print(f"Vorgeschlagenes k (Silhouette-Max): {k_silhouette}")
print(f"Aktuell gewaehltes k:               10")

# --- Plot 1: Elbow-Diagramm mit Knee ---
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(k_list, inertias, "bx-", label="WCSS")
if k_elbow is not None:
    ax.axvline(x=k_elbow, color="g", linestyle="--",
               label=f"Knee: k = {k_elbow}")
ax.axvline(x=10, color="r", linestyle="--",
           label="Implementierung: k = 10")
ax.set_xlabel("Anzahl Cluster (k)")
ax.set_ylabel("Inertia")
ax.set_title("K-Means Parametersuche: Elbow-Methode (Knee-Detektion)")
ax.legend()
plt.tight_layout()
plt.savefig("results/k_means_ellenbow.png", dpi=100, bbox_inches="tight")
plt.show()

# --- Plot 2: Silhouette-Score ---
fig, ax = plt.subplots(figsize=(8, 5))
ax.plot(k_list, silhouette_scores, "bx-", label="Silhouette Score")
ax.axvline(x=k_silhouette, color="g", linestyle="--",
           label=f"Maximum: k = {k_silhouette}")
ax.axvline(x=10, color="r", linestyle="--",
           label="Implementierung: k = 10")
ax.set_xlabel("Anzahl Cluster (k)")
ax.set_ylabel("Silhouette Score")
ax.set_title("K-Means Parametersuche: Silhouette-Methode")
ax.legend()
plt.tight_layout()
plt.savefig("results/k_means_silhouette.png", dpi=100, bbox_inches="tight")
plt.show()


# In[5]:


# ==========================================
# DBSCAN Parametersuche: k-Distanz-Plot
# Bestimmt eps datengetrieben (Cosinus-Distanz, k = MIN_SAMPLES)
# ==========================================
try:
    from kneed import KneeLocator
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'kneed'])
    from kneed import KneeLocator

from sklearn.neighbors import NearestNeighbors
import numpy as np
import matplotlib.pyplot as plt

# Parameter analog zur DBSCAN-Implementierung
DBSCAN_MIN_SAMPLES = 2
DBSCAN_METRIC = 'cosine'

# Nearest Neighbors auf TF-IDF mit Cosinus-Distanz
nbrs = NearestNeighbors(
    n_neighbors=DBSCAN_MIN_SAMPLES,
    metric=DBSCAN_METRIC,
)
nbrs.fit(X_tfidf)
distances, _ = nbrs.kneighbors(X_tfidf)

# Distanz zum k-ten Nachbarn (k = MIN_SAMPLES), aufsteigend sortiert
k_distances = np.sort(distances[:, -1])


x_idx = np.arange(len(k_distances))
detected_direction, detected_curve = find_shape(x_idx, k_distances)
print(f"find_shape() erkennt: curve='{detected_curve}', direction='{detected_direction}'")

# Knick automatisch lokalisieren
knee = KneeLocator(
    np.arange(len(k_distances)),
    k_distances,
    curve=detected_curve,
    direction=detected_direction
)

eps_suggested = k_distances[knee.knee] if knee.knee is not None else None
if eps_suggested is not None:
    print(f'Vorgeschlagener eps (Knee): {eps_suggested:.4f} (Index {knee.knee})')
else:
    print('Kein eindeutiger Knick gefunden.')
print(f'Aktuell gewaehlter eps:     0.60')

# Plot
plt.figure(figsize=(8, 5))
plt.plot(k_distances, 'b-', label='k-Distanz (sortiert)')
if eps_suggested is not None:
    plt.axhline(y=eps_suggested, color='g', linestyle='--',
                label=f'Knee: eps = {eps_suggested:.3f}')
    plt.axvline(x=knee.knee, color='g', linestyle=':')
plt.xlabel('Punkte (sortiert)')
plt.ylabel(f'Cosinus-Distanz zum {DBSCAN_MIN_SAMPLES}. Nachbarn')
plt.title('k-Distanz-Plot fuer DBSCAN')
plt.legend()
plt.tight_layout()
plt.savefig('results/dbscan_k_distance.png', dpi=100, bbox_inches='tight')
plt.show()


# In[6]:


# ==========================================
# Drain3 Parametersuche: 1D-Sweep ueber sim_th (mit Variante depth)
# Bestimmt sim_th datengetrieben ueber Knee in der Cluster-Anzahl-Kurve
# ==========================================
try:
    from kneed import KneeLocator
except ImportError:
    import subprocess, sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'kneed'])
    from kneed import KneeLocator

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
import numpy as np
import matplotlib.pyplot as plt

# Logs einlesen (selbststaendig, unabhaengig von vorherigen Zellen)
with open('Mixed_10k.log', 'r', encoding='utf-8', errors='ignore') as f:
    drain_logs = [line.strip() for line in f if line.strip()]
print(f'Geladen: {len(drain_logs)} Logs')

# Sweep-Bereiche
sim_th_values = [round(0.1 * i, 1) for i in range(1, 10)]   # 0.1 ... 0.9
depth_values  = [3, 4, 5]

# Ergebnis-Matrix: rows = depth, cols = sim_th
results = np.zeros((len(depth_values), len(sim_th_values)), dtype=int)

for i, depth in enumerate(depth_values):
    for j, sim_th in enumerate(sim_th_values):
        cfg = TemplateMinerConfig()
        cfg.drain_sim_th = sim_th
        cfg.drain_depth  = depth
        miner = TemplateMiner(config=cfg)
        cluster_ids = set()
        for log in drain_logs:
            res = miner.add_log_message(log)
            cluster_ids.add(res.get('cluster_id'))
        results[i, j] = len(cluster_ids)
        print(f'depth={depth}, sim_th={sim_th}: {results[i, j]} Cluster')

# Plot: 1 Linie pro depth, x = sim_th, y = Cluster-Anzahl (log-Skala)
plt.figure(figsize=(9, 5.5))
colors = ['tab:blue', 'tab:orange', 'tab:green']

for i, depth in enumerate(depth_values):
    plt.plot(sim_th_values, results[i], 'o-', color=colors[i],
             label=f'depth = {depth}')
    try:
        knee = KneeLocator(sim_th_values, results[i].tolist(),
                           curve='convex', direction='increasing')
        if knee.knee is not None:
            idx = sim_th_values.index(knee.knee)
            plt.axvline(x=knee.knee, color=colors[i], linestyle=':',
                        alpha=0.6,
                        label=f'Knee depth={depth}: sim_th = {knee.knee}')
            print(f'depth={depth}: Knee bei sim_th = {knee.knee}, '
                  f'Cluster = {results[i, idx]}')
    except Exception as e:
        print(f'depth={depth}: kein Knee ({e})')

# Referenzlinie fuer aktuelle Implementierung
plt.axvline(x=0.2, color='red', linestyle='--', alpha=0.5,
            label='Implementierung: sim_th = 0.2')

plt.xlabel('sim_th')
plt.ylabel('Anzahl Cluster (log-Skala)')
plt.title('Drain3 Parametersuche: Cluster-Anzahl vs sim_th')
plt.legend(loc='upper left', fontsize=8)
plt.grid(True, alpha=0.3, which='both')
plt.yscale('log')
plt.tight_layout()
plt.savefig('results/drain3_sweep.png', dpi=100, bbox_inches='tight')
plt.show()

# Tabelle ausgeben
print()
print('=== Drain3 Cluster-Anzahl: depth x sim_th ===')
header = f'{"depth":>6s} | ' + ' | '.join(f'{v:>5.1f}' for v in sim_th_values)
print(header)
print('-' * len(header))
for i, depth in enumerate(depth_values):
    row = f'{depth:>6d} | ' + ' | '.join(f'{c:>5d}' for c in results[i])
    print(row)


# In[12]:


from sqlalchemy import create_engine, text
import os

PGVECTOR_DB_URL = os.environ.get(
    'PGVECTOR_DB_URL',
    'postgresql+psycopg://postgres:postgres@localhost:5432/vectordb'
)

# ==========================================
# SQL Schema für PostgreSQL mit pgvector (Vereinfacht)
# ==========================================

sql_schema = """
-- Erweiterung für Vektor-Operationen aktivieren
CREATE EXTENSION IF NOT EXISTS vector;

-- Tabelle: log (Haupt-Log-Einträge mit Embedding)
CREATE TABLE IF NOT EXISTS log (
    id SERIAL PRIMARY KEY,
    message TEXT NOT NULL,
    embedding vector(384),  -- Dimension für all-MiniLM-L6-v2
    processed BOOLEAN DEFAULT FALSE,
    log_cluster_id INTEGER
);

-- HNSW-Index für schnelle Vektorsuche (Cosine-Distanz)
CREATE INDEX IF NOT EXISTS idx_log_embedding_hnsw ON log 
    USING hnsw (embedding vector_cosine_ops);

-- Tabelle: avg_embedding (Durchschnitts-Embeddings pro Cluster)
CREATE TABLE IF NOT EXISTS avg_embedding (
    id SERIAL PRIMARY KEY,
    avg_embedding vector(384) NOT NULL,
    log_cluster_id INTEGER NOT NULL UNIQUE
);

-- HNSW-Index für avg_embedding
CREATE INDEX IF NOT EXISTS idx_avg_embedding_hnsw ON avg_embedding 
    USING hnsw (avg_embedding vector_cosine_ops);
"""

# ==========================================
# SQL für cluster_batch-Algorithmus
# ==========================================
# Konstante: COSINE_DISTANCE (einheitlicher Schwellwert)

sql_cluster_batch = """
-- ============================================================
-- CLUSTER_BATCH ALGORITHMUS
-- ============================================================
-- Pseudocode:
-- 1. Lies aktuellen Cluster-Zaehler aus der DB (0 wenn leer)
-- 2. Füge alle Logs des Batches als unverarbeitet ein
-- 3. Für jeden unverarbeiteten Log:
--    a) Suche naechsten Zentroid in avg_embedding mit
--       cosine_distance <= COSINE_DISTANCE
--    b) Falls gefunden: weise Log diesem Cluster zu
--    c) Falls nicht: erstelle neuen Cluster (cluster_count + 1)
--    d) Aktualisiere avg_embedding des betroffenen Clusters sofort
--       (inkrementell, damit nachfolgende Logs davon profitieren)
-- ============================================================

-- Schritt 1: Aktuellen Cluster-Zaehler bestimmen
SELECT COALESCE(MAX(log_cluster_id), 0) FROM log;

-- Schritt 2: Logs einfügen
INSERT INTO log (message, embedding, processed)
VALUES (:msg, :emb, FALSE);

-- Schritt 3a: Naechsten Zentroid suchen
WITH target AS (SELECT embedding FROM log WHERE id = :id)
SELECT ae.log_cluster_id
FROM avg_embedding ae, target t
WHERE (ae.avg_embedding <=> t.embedding) <= :threshold
ORDER BY ae.avg_embedding <=> t.embedding
LIMIT 1;

-- Schritt 3b/c: Log einem Cluster zuweisen
UPDATE log
SET log_cluster_id = :cid,
    processed = TRUE
WHERE id = :id;

-- Schritt 3d: avg_embedding inkrementell aktualisieren (UPSERT)
INSERT INTO avg_embedding (log_cluster_id, avg_embedding)
SELECT log_cluster_id, AVG(embedding)
FROM log
WHERE embedding IS NOT NULL
  AND log_cluster_id = :cid
GROUP BY log_cluster_id
ON CONFLICT (log_cluster_id) DO UPDATE
    SET avg_embedding = EXCLUDED.avg_embedding;
"""

engine = create_engine(PGVECTOR_DB_URL)

with engine.connect() as conn:
    # Schema erstellen
    conn.execute(text(sql_schema))
    conn.commit()

print('SQL Schema und Clustering-Statement erstellt!')


# In[13]:


# ==========================================
# Implementierung Clustering mit pg_vector
# ==========================================
import numpy as np
from sqlalchemy import text


def cluster_batch(logs, embeddings, threshold, conn):
    cluster_count = conn.execute(
        text('SELECT COALESCE(MAX(log_cluster_id), 0) FROM log')
    ).scalar()

    for msg, emb in zip(logs, embeddings):
        emb_str = '[' + ','.join(map(str, emb.tolist())) + ']'
        conn.execute(text(
            'INSERT INTO log (message, embedding, processed) VALUES (:msg, :emb, FALSE)'
        ), {'msg': msg, 'emb': emb_str})
    conn.commit()

    log_ids = conn.execute(text(
        'SELECT id FROM log WHERE processed = FALSE AND embedding IS NOT NULL ORDER BY id'
    )).fetchall()

    for (log_id,) in log_ids:
        sim_cluster = conn.execute(text('''
            WITH target AS (SELECT embedding FROM log WHERE id = :id)
            SELECT ae.log_cluster_id FROM avg_embedding ae, target t
            WHERE (ae.avg_embedding <=> t.embedding) <= :threshold
            ORDER BY ae.avg_embedding <=> t.embedding LIMIT 1
        '''), {'id': log_id, 'threshold': threshold}).fetchone()

        if sim_cluster:
            cid = sim_cluster[0]
        else:
            cluster_count += 1
            cid = cluster_count

        conn.execute(text(
            'UPDATE log SET log_cluster_id = :cid, processed = TRUE WHERE id = :id'
        ), {'cid': cid, 'id': log_id})

        conn.execute(text('''
            INSERT INTO avg_embedding (log_cluster_id, avg_embedding)
            SELECT log_cluster_id, AVG(embedding) FROM log
            WHERE embedding IS NOT NULL AND log_cluster_id = :cid
            GROUP BY log_cluster_id
            ON CONFLICT (log_cluster_id) DO UPDATE
                SET avg_embedding = EXCLUDED.avg_embedding
        '''), {'cid': cid})

    conn.commit()

    rows = conn.execute(text(
        'SELECT id, log_cluster_id FROM log ORDER BY id'
    )).fetchall()
    return np.array([r[1] if r[1] is not None else -1 for r in rows])


# In[14]:


# ==========================================
# pgvector Parametersuche: 1D-Sweep ueber COSINE_DISTANCE
# Zwei Diagramme: Cluster-Anzahl und Silhouette-Score
# ==========================================
import os
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sentence_transformers import SentenceTransformer
from sqlalchemy import create_engine, text
from sklearn.metrics import silhouette_score

# ---------- Konfiguration ----------
PGVECTOR_EMBEDDING_MODEL = 'sentence-transformers/all-MiniLM-L6-v2'

# Stichprobengroesse fuer den Sweep. 2000 = Loghub-2k Skala,
# 10000 fuer den vollen Datensatz (Laufzeit ca. 30-60 min).
SWEEP_SAMPLE_SIZE = 2000

# Sweep-Bereich
THRESHOLD_VALUES = [0.1,0.2,0.3, 0.4, 0.5, 0.6, 0.7]

# ---------- Logs laden ----------
with open('Mixed_10k.log', 'r', encoding='utf-8', errors='ignore') as f:
    all_logs = [line.strip() for line in f if line.strip()]

rng = np.random.default_rng(42)
if SWEEP_SAMPLE_SIZE < len(all_logs):
    sample_idx = rng.choice(len(all_logs), SWEEP_SAMPLE_SIZE, replace=False)
    logs_sample = [all_logs[i] for i in sample_idx]
else:
    logs_sample = all_logs
n = len(logs_sample)
print(f'Stichprobe: {n} Logs')

# ---------- Embeddings einmal vorberechnen ----------
print('Berechne Embeddings (einmalig) ...')
model = SentenceTransformer(PGVECTOR_EMBEDDING_MODEL)
embeddings = model.encode(logs_sample, show_progress_bar=True)
print(f'Embedding-Matrix: {embeddings.shape}')

# DB-Verbindung
engine = create_engine(PGVECTOR_DB_URL)


# ---------- Sweep ausfuehren ----------
cluster_counts = []
silhouette_scores = []

for threshold in THRESHOLD_VALUES:
    with engine.connect() as conn:
        conn.execute(text('TRUNCATE log, avg_embedding RESTART IDENTITY'))
        conn.commit()
        t0 = time.time()
        labels = cluster_batch(logs_sample, embeddings, threshold, conn)

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    try:
        mask = labels >= 0
        if len(set(labels[mask])) > 1:
            sample_size = min(2000, mask.sum())
            sil = silhouette_score(embeddings[mask], labels[mask],
                                   metric='cosine', sample_size=sample_size,
                                   random_state=42)
        else:
            sil = np.nan
    except Exception as e:
        sil = np.nan
        print(f'  silhouette error: {e}')

    cluster_counts.append(n_clusters)
    silhouette_scores.append(sil)
    dt = time.time() - t0
    print(f'threshold={threshold}: {n_clusters} Cluster, sil={sil:.4f}  ({dt:.1f}s)')

# ---------- Ergebnis-Tabelle ----------
df_results = pd.DataFrame({
    'threshold': THRESHOLD_VALUES,
    'n_clusters': cluster_counts,
    'silhouette': silhouette_scores
})
print('\n=== Sweep-Ergebnis ===')
print(df_results.to_string(index=False, float_format=lambda x: f'{x:.4f}'))

df_results.to_csv('results/pgvector_sweep.csv', index=False)

# ---------- Diagramme ----------
fig, axes = plt.subplots(1, 2, figsize=(12, 4))

axes[0].plot(THRESHOLD_VALUES, cluster_counts, marker='o')
axes[0].set_xlabel('Cosine-Distanz-Schwelle')
axes[0].set_ylabel('Anzahl Cluster')
axes[0].set_title(f'pgvector: Cluster-Anzahl (n={n})')
axes[0].grid(True)

axes[1].plot(THRESHOLD_VALUES, silhouette_scores, marker='o', color='tab:green')
axes[1].set_xlabel('Cosine-Distanz-Schwelle')
axes[1].set_ylabel('Silhouette-Score (cosine)')
axes[1].set_title(f'pgvector: Silhouette-Score (n={n})')
axes[1].grid(True)

plt.tight_layout()
plt.savefig('results/pgvector_sweep.png', dpi=100, bbox_inches='tight')
plt.show()


# In[ ]:


# ===== CLUSTERING VERGLEICH =====
# Alle drei Algorithmen auf die Logs anwenden und Ergebnisse in df_labeled speichern

# ===== PARAMETER KONFIGURATION =====

# TF-IDF Parameter
TFIDF_MAX_FEATURES = 1000
TFIDF_MIN_DF = 2
TFIDF_MAX_DF = 0.95

# K-Means Parameter
KMEANS_N_CLUSTERS = 13
KMEANS_RANDOM_STATE = 42

# DBSCAN Parameter
DBSCAN_EPS = 0.4
DBSCAN_MIN_SAMPLES = 2
DBSCAN_METRIC = 'cosine'

# Drain3 Parameter
DRAIN_SIM_TH = 0.2
DRAIN_DEPTH=4


# pgvector Parameter
import os
PGVECTOR_COSINE_DISTANCE = 0.3
PGVECTOR_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# DB-URL aus Umgebungsvariable (Docker) oder Fallback auf localhost
PGVECTOR_DB_URL = os.environ.get("PGVECTOR_DB_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/vectordb")

# MinHash LSH Parameter
MINHASH_NUM_PERM = 128
MINHASH_THRESHOLD = 0.3
MINHASH_NGRAM_SIZE = 2

# Brain Parameter
BRAIN_THRESHOLD = 5
BRAIN_REGEX = [r'((\d+\.){3}\d+,?)+', r'/.+?\s ', r'\d+']
BRAIN_DELIMITER = []
BRAIN_DATASET = 'OpenStack'


import sys
import datetime as _dt
sys.path.insert(0, '/Users/max/Code/BA/Brain')
from Brain import Brain

# ===== IMPORTS =====
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans, DBSCAN
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from datasketch import MinHash, MinHashLSH

# ===== TF-IDF VEKTORISIERUNG =====
# Logs aus df_labeled extrahieren (ohne Zeilenumbrüche)
logs_clean = df_labeled['log'].str.strip().tolist()

vectorizer = TfidfVectorizer(
    max_features=TFIDF_MAX_FEATURES,
    min_df=TFIDF_MIN_DF,
    max_df=TFIDF_MAX_DF
)
X_tfidf = vectorizer.fit_transform(logs_clean)
print(f"TF-IDF Matrix: {X_tfidf.shape}")

# ===== K-MEANS CLUSTERING =====
kmeans = KMeans(
    n_clusters=KMEANS_N_CLUSTERS,
    random_state=KMEANS_RANDOM_STATE
)
df_labeled['kmeans_cluster_id'] = kmeans.fit_predict(X_tfidf)

# ===== DBSCAN CLUSTERING =====
dbscan = DBSCAN(
    eps=DBSCAN_EPS,
    min_samples=DBSCAN_MIN_SAMPLES,
    metric=DBSCAN_METRIC
)
df_labeled['dbscan_cluster_id'] = dbscan.fit_predict(X_tfidf)

# ===== DRAIN3 CLUSTERING =====
drain_config = TemplateMinerConfig()
drain_config.drain_sim_th = DRAIN_SIM_TH

template_miner = TemplateMiner(config=drain_config)

drain_cluster_ids = []
for log in df_labeled['log']:
    result = template_miner.add_log_message(log)
    drain_cluster_ids.append(result.get("cluster_id"))

df_labeled['drain_cluster_id'] = drain_cluster_ids

# ===== PGVECTOR CLUSTERING =====
from sqlalchemy import create_engine, text
from sentence_transformers import SentenceTransformer
import numpy as np

print("pgvector: Verbinde mit Datenbank...")
engine = create_engine(PGVECTOR_DB_URL)

print("pgvector: Generiere Embeddings...")
model = SentenceTransformer(PGVECTOR_EMBEDDING_MODEL)
embeddings = model.encode(logs_clean, show_progress_bar=True)

with engine.connect() as conn:
    conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    conn.commit()
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS log (
            id SERIAL PRIMARY KEY,
            message TEXT NOT NULL,
            embedding vector(384),
            processed BOOLEAN DEFAULT FALSE,
            log_cluster_id INTEGER
        )
    """))
    conn.execute(text("""
        CREATE TABLE IF NOT EXISTS avg_embedding (
            id SERIAL PRIMARY KEY,
            avg_embedding vector(384) NOT NULL,
            log_cluster_id INTEGER NOT NULL UNIQUE
        )
    """))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_log_embedding_hnsw ON log USING hnsw (embedding vector_cosine_ops)"))
    conn.execute(text("CREATE INDEX IF NOT EXISTS idx_avg_embedding_hnsw ON avg_embedding USING hnsw (avg_embedding vector_cosine_ops)"))
    conn.commit()
    conn.execute(text("TRUNCATE log, avg_embedding RESTART IDENTITY"))
    conn.commit()


print("pgvector: Clustering...")
with engine.connect() as conn:
    labels = cluster_batch(logs_clean, embeddings, PGVECTOR_COSINE_DISTANCE, conn)

df_labeled['pgvector_cluster_id'] = labels
print(f"pgvector: Fertig! {df_labeled['pgvector_cluster_id'].nunique()} Cluster erstellt")

# ===== MINHASH LSH CLUSTERING =====
def minhash_tokenize(log_line, n=MINHASH_NGRAM_SIZE):
    words = log_line.split()
    if len(words) < n:
        return set(words) if words else {log_line}
    return set(' '.join(words[i:i+n]) for i in range(len(words) - n + 1))

print("MinHash LSH: Erzeuge MinHash-Signaturen...")
minhashes = []
for log in logs_clean:
    m = MinHash(num_perm=MINHASH_NUM_PERM)
    for shingle in minhash_tokenize(log):
        m.update(shingle.encode('utf8'))
    minhashes.append(m)

print("MinHash LSH: Baue LSH-Index...")
lsh_index = MinHashLSH(threshold=MINHASH_THRESHOLD, num_perm=MINHASH_NUM_PERM)
for i, m in enumerate(minhashes):
    lsh_index.insert(str(i), m)

print("MinHash LSH: Clustering via Union-Find...")
_parent = list(range(len(logs_clean)))

def _uf_find(x):
    while _parent[x] != x:
        _parent[x] = _parent[_parent[x]]
        x = _parent[x]
    return x

def _uf_union(a, b):
    ra, rb = _uf_find(a), _uf_find(b)
    if ra != rb:
        _parent[ra] = rb

for i, m in enumerate(minhashes):
    neighbors = lsh_index.query(m)
    for nb in neighbors:
        _uf_union(i, int(nb))

root_to_cluster = {}
minhash_labels = []
next_cluster_id = 0
for i in range(len(logs_clean)):
    root = _uf_find(i)
    if root not in root_to_cluster:
        root_to_cluster[root] = next_cluster_id
        next_cluster_id += 1
    minhash_labels.append(root_to_cluster[root])

df_labeled['minhash_cluster_id'] = minhash_labels
print(f"MinHash LSH: Fertig! {df_labeled['minhash_cluster_id'].nunique()} Cluster erstellt")


# ===== BRAIN CLUSTERING =====
print("Brain: Starte Parsing...")
_brain_starttime = _dt.datetime.now()
_brain_df_input = pd.DataFrame(index=range(len(logs_clean)))
_brain_df_output, _ = Brain.parse(
    logs_clean, BRAIN_REGEX, BRAIN_DATASET, BRAIN_THRESHOLD,
    BRAIN_DELIMITER, _brain_starttime, efficiency=False, df_input=_brain_df_input)

# EventId (z.B. "E0", "E1", ...) → Integer-Cluster-ID
_event_ids = _brain_df_output['EventId'].tolist()
_eid_map = {eid: i for i, eid in enumerate(dict.fromkeys(_event_ids))}
df_labeled['brain_cluster_id'] = [_eid_map[eid] for eid in _event_ids]
print(f"Brain: {df_labeled['brain_cluster_id'].nunique()} Cluster (threshold={BRAIN_THRESHOLD})")

print("\n" + "="*50)
# ===== ZUSAMMENFASSUNG =====
print("\n" + "="*50)
print("CLUSTERING ERGEBNISSE")
print("="*50)
print(f"K-Means:  {df_labeled['kmeans_cluster_id'].nunique()} Cluster (k={KMEANS_N_CLUSTERS})")
print(f"DBSCAN:   {df_labeled['dbscan_cluster_id'].nunique()} Cluster (eps={DBSCAN_EPS}, min_samples={DBSCAN_MIN_SAMPLES})")
print(f"Drain3:   {df_labeled['drain_cluster_id'].nunique()} Cluster (sim_th={DRAIN_SIM_TH}, depth={DRAIN_DEPTH})")
print(f"pgvector: {df_labeled['pgvector_cluster_id'].nunique()} Cluster (threshold={PGVECTOR_COSINE_DISTANCE})")
print(f"MinHash:  {df_labeled['minhash_cluster_id'].nunique()} Cluster (threshold={MINHASH_THRESHOLD}, num_perm={MINHASH_NUM_PERM}, ngram={MINHASH_NGRAM_SIZE})")
print(f"Brain:    {df_labeled['brain_cluster_id'].nunique()} Cluster (threshold={BRAIN_THRESHOLD})")
print("="*50)


# In[25]:


# ===== CLUSTERING EVALUATION =====
# Vergleich der Algorithmen mit den manuellen Ground-Truth-Labels (cluster_id)

from sklearn.metrics import adjusted_rand_score, v_measure_score, homogeneity_score, completeness_score
import pandas as pd

# Algorithmen und ihre Spalten
algorithms = {
    'K-Means': 'kmeans_cluster_id',
    'DBSCAN': 'dbscan_cluster_id',
    'Drain3': 'drain_cluster_id',
    'pgvector': 'pgvector_cluster_id',
    'MinHash LSH': 'minhash_cluster_id',
    'Brain': 'brain_cluster_id'
}

# Ground-Truth (manuell gelabelt)
ground_truth = df_labeled['cluster_id']

# Ergebnisse sammeln
results = []

print("="*70)
print("CLUSTERING EVALUATION - Vergleich mit Ground-Truth (cluster_id)")
print("="*70)
print()

for name, col in algorithms.items():
    pred = df_labeled[col]

    # Metriken berechnen
    ari = adjusted_rand_score(ground_truth, pred) * 100
    v_measure = v_measure_score(ground_truth, pred) * 100
    homogeneity = homogeneity_score(ground_truth, pred) * 100
    completeness = completeness_score(ground_truth, pred) * 100

    results.append({
        'Algorithmus': name,
        'ARI (%)': round(ari, 1),
        'V-Measure (%)': round(v_measure, 1),
        'Homogenität (%)': round(homogeneity, 1),
        'Vollständigkeit (%)': round(completeness, 1),
        'Anzahl Cluster': df_labeled[col].nunique()
    })

    print(f"📊 {name}:")
    print(f"   ARI:            {ari:6.1f}%  (Paar-Übereinstimmung, zufallsbereinigt)")
    print(f"   V-Measure:      {v_measure:6.1f}%  (Homogenität + Vollständigkeit)")
    print(f"   Homogenität:    {homogeneity:6.1f}%  (Cluster-Reinheit)")
    print(f"   Vollständigkeit:{completeness:6.1f}%  (Klassen zusammengehalten)")
    print()

print("="*70)

# Ergebnis-DataFrame für einfachen Vergleich
df_evaluation = pd.DataFrame(results)
print("\nZusammenfassung als Tabelle:")
df_evaluation.to_csv('./results/clustering_evaluation_results.csv', index=False)
df_evaluation


# In[26]:


import sys
import datetime as _dt
sys.path.insert(0, '/Users/max/Code/BA/Brain')
from Brain import Brain

# ===== MULTI-RUN CLUSTERING EVALUATION =====
# 5-fache Ausführung aller Algorithmen mit verschiedenen Random States
# Berechnung der Durchschnittswerte für ARI, V-Measure, Homogenität und Vollständigkeit

import os
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import adjusted_rand_score, v_measure_score, homogeneity_score, completeness_score
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from sqlalchemy import create_engine, text
from sentence_transformers import SentenceTransformer
from datasketch import MinHash, MinHashLSH
import random

# ===== KONFIGURATION =====
RANDOM_SEEDS = [42, 123, 456, 789, 1011]
N_RUNS = len(RANDOM_SEEDS)

# Parameter (aus Cell 9)
TFIDF_MAX_FEATURES = 1000
TFIDF_MIN_DF = 2
TFIDF_MAX_DF = 0.95
KMEANS_N_CLUSTERS = 13
DBSCAN_EPS = 0.4
DBSCAN_MIN_SAMPLES = 2
DBSCAN_METRIC = 'cosine'
DRAIN_SIM_TH = 0.2
DRAIN_DEPTH = 3
DRAIN_MAX_CHILDREN = 100
PGVECTOR_INITIAL_COSINE_DISTANCE = 0.3
PGVECTOR_RECLUSTER_COSINE_DISTANCE = 0.2
PGVECTOR_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
# DB-URL aus Umgebungsvariable (Docker) oder Fallback auf localhost
PGVECTOR_DB_URL = os.environ.get("PGVECTOR_DB_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/vectordb")
PGVECTOR_INITIAL_RATIO = 0.5
MINHASH_NUM_PERM = 128
MINHASH_THRESHOLD = 0.5
MINHASH_NGRAM_SIZE = 3

# Ground-Truth Labels
ground_truth = df_labeled['cluster_id'].values
logs_original = df_labeled['log'].str.strip().tolist()

# Ergebnis-Sammlung
all_results = {alg: {'ari': [], 'v_measure': [], 'homogeneity': [], 'completeness': []} 
               for alg in ['K-Means', 'DBSCAN', 'Drain3', 'pgvector', 'MinHash LSH', 'Brain']}

# Sentence Transformer einmal laden
print("Lade Sentence Transformer Modell...")
model = SentenceTransformer(PGVECTOR_EMBEDDING_MODEL)
engine = create_engine(PGVECTOR_DB_URL)

print(f"\n{'='*70}")
print(f"MULTI-RUN CLUSTERING EVALUATION - {N_RUNS} Durchläufe")
print(f"{'='*70}\n")

for run_idx, seed in enumerate(RANDOM_SEEDS):
    print(f"\n🔄 Durchlauf {run_idx + 1}/{N_RUNS} (Seed: {seed})")
    print("-" * 50)

    # Daten shufflen mit aktuellem Seed
    random.seed(seed)
    np.random.seed(seed)

    indices = list(range(len(logs_original)))
    random.shuffle(indices)

    logs_shuffled = [logs_original[i] for i in indices]
    ground_truth_shuffled = ground_truth[indices]

    # TF-IDF Vektorisierung
    vectorizer = TfidfVectorizer(max_features=TFIDF_MAX_FEATURES, min_df=TFIDF_MIN_DF, max_df=TFIDF_MAX_DF)
    X_tfidf = vectorizer.fit_transform(logs_shuffled)

    # ===== K-MEANS =====
    kmeans = KMeans(n_clusters=KMEANS_N_CLUSTERS, random_state=seed)
    kmeans_labels = kmeans.fit_predict(X_tfidf)

    all_results['K-Means']['ari'].append(adjusted_rand_score(ground_truth_shuffled, kmeans_labels))
    all_results['K-Means']['v_measure'].append(v_measure_score(ground_truth_shuffled, kmeans_labels))
    all_results['K-Means']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, kmeans_labels))
    all_results['K-Means']['completeness'].append(completeness_score(ground_truth_shuffled, kmeans_labels))

    # ===== DBSCAN =====
    dbscan = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric=DBSCAN_METRIC)
    dbscan_labels = dbscan.fit_predict(X_tfidf)

    all_results['DBSCAN']['ari'].append(adjusted_rand_score(ground_truth_shuffled, dbscan_labels))
    all_results['DBSCAN']['v_measure'].append(v_measure_score(ground_truth_shuffled, dbscan_labels))
    all_results['DBSCAN']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, dbscan_labels))
    all_results['DBSCAN']['completeness'].append(completeness_score(ground_truth_shuffled, dbscan_labels))

    # ===== DRAIN3 =====
    drain_config = TemplateMinerConfig()
    drain_config.drain_sim_th = DRAIN_SIM_TH
    drain_config.drain_depth = DRAIN_DEPTH
    drain_config.drain_max_children = DRAIN_MAX_CHILDREN
    template_miner = TemplateMiner(config=drain_config)

    drain_labels = []
    for log in logs_shuffled:
        result = template_miner.add_log_message(log)
        drain_labels.append(result.get("cluster_id"))

    all_results['Drain3']['ari'].append(adjusted_rand_score(ground_truth_shuffled, drain_labels))
    all_results['Drain3']['v_measure'].append(v_measure_score(ground_truth_shuffled, drain_labels))
    all_results['Drain3']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, drain_labels))
    all_results['Drain3']['completeness'].append(completeness_score(ground_truth_shuffled, drain_labels))

    # ===== PGVECTOR =====
    # Embeddings generieren (in geshuffelter Reihenfolge)
    embeddings = model.encode(logs_shuffled, show_progress_bar=False)

    # Datenbank vorbereiten
    with engine.connect() as conn:
        conn.execute(text("TRUNCATE log, avg_embedding RESTART IDENTITY"))
        conn.commit()

        # Logs einfügen
        for i, (msg, emb) in enumerate(zip(logs_shuffled, embeddings)):
            embedding_str = "[" + ",".join(map(str, emb.tolist())) + "]"
            conn.execute(text("""
                INSERT INTO log (message, embedding, processed) 
                VALUES (:msg, CAST(:emb AS vector), FALSE)
            """), {"msg": msg, "emb": embedding_str})
        conn.commit()

    split_idx = int(len(logs_shuffled) * PGVECTOR_INITIAL_RATIO)

    # Initial Clustering
    with engine.connect() as conn:
        conn.execute(text("UPDATE log SET processed = TRUE WHERE id > :split_idx"), {"split_idx": split_idx})
        conn.commit()

        candidates = conn.execute(text("""
            SELECT id FROM log WHERE processed = FALSE AND embedding IS NOT NULL ORDER BY id
        """)).fetchall()

        for (log_id,) in candidates:
            check = conn.execute(text("SELECT log_cluster_id FROM log WHERE id = :id"), {"id": log_id}).fetchone()
            if check and check[0] is not None:
                continue

            similar = conn.execute(text("""
                WITH target AS (SELECT embedding FROM log WHERE id = :id)
                SELECT l.id FROM log l, target t
                WHERE l.processed = FALSE AND l.embedding IS NOT NULL
                  AND (l.embedding <=> t.embedding) < :threshold
                ORDER BY l.embedding <=> t.embedding
            """), {"id": log_id, "threshold": PGVECTOR_INITIAL_COSINE_DISTANCE}).fetchall()

            if similar:
                similar_ids = [s[0] for s in similar]
                max_cluster = conn.execute(text("SELECT COALESCE(MAX(log_cluster_id), 0) FROM log")).fetchone()[0]
                new_cluster_id = max_cluster + 1
                conn.execute(text("""
                    UPDATE log SET log_cluster_id = :cluster_id, processed = TRUE WHERE id = ANY(:ids)
                """), {"cluster_id": new_cluster_id, "ids": similar_ids})
        conn.commit()

        # avg_embedding füllen
        conn.execute(text("""
            INSERT INTO avg_embedding (log_cluster_id, avg_embedding)
            SELECT log_cluster_id, AVG(embedding) FROM log 
            WHERE embedding IS NOT NULL AND log_cluster_id IS NOT NULL
            GROUP BY log_cluster_id
            ON CONFLICT (log_cluster_id) DO UPDATE SET avg_embedding = EXCLUDED.avg_embedding
        """))
        conn.commit()

    # Re-Clustering
    with engine.connect() as conn:
        conn.execute(text("UPDATE log SET processed = FALSE WHERE id > :split_idx"), {"split_idx": split_idx})
        conn.commit()

        unprocessed = conn.execute(text("""
            SELECT id FROM log WHERE processed = FALSE AND embedding IS NOT NULL ORDER BY id
        """)).fetchall()

        for (log_id,) in unprocessed:
            similar_cluster = conn.execute(text("""
                WITH target AS (SELECT embedding FROM log WHERE id = :id)
                SELECT ae.log_cluster_id FROM avg_embedding ae, target t
                WHERE ae.avg_embedding IS NOT NULL
                  AND (ae.avg_embedding <=> t.embedding) <= :threshold
                ORDER BY ae.avg_embedding <=> t.embedding LIMIT 1
            """), {"id": log_id, "threshold": PGVECTOR_RECLUSTER_COSINE_DISTANCE}).fetchone()

            if similar_cluster:
                conn.execute(text("""
                    UPDATE log SET log_cluster_id = :cluster_id, processed = TRUE WHERE id = :id
                """), {"cluster_id": similar_cluster[0], "id": log_id})
            else:
                similar_log = conn.execute(text("""
                    WITH target AS (SELECT embedding FROM log WHERE id = :id)
                    SELECT l.log_cluster_id FROM log l, target t
                    WHERE l.processed = TRUE AND l.log_cluster_id IS NOT NULL
                      AND l.embedding IS NOT NULL
                      AND (l.embedding <=> t.embedding) < :threshold
                    ORDER BY l.embedding <=> t.embedding LIMIT 1
                """), {"id": log_id, "threshold": PGVECTOR_INITIAL_COSINE_DISTANCE}).fetchone()

                if similar_log:
                    conn.execute(text("""
                        UPDATE log SET log_cluster_id = :cluster_id, processed = TRUE WHERE id = :id
                    """), {"cluster_id": similar_log[0], "id": log_id})
                else:
                    max_cluster = conn.execute(text("SELECT COALESCE(MAX(log_cluster_id), 0) FROM log")).fetchone()[0]
                    new_cluster_id = max_cluster + 1
                    conn.execute(text("""
                        UPDATE log SET log_cluster_id = :cluster_id, processed = TRUE WHERE id = :id
                    """), {"cluster_id": new_cluster_id, "id": log_id})

            conn.execute(text("""
                INSERT INTO avg_embedding (log_cluster_id, avg_embedding)
                SELECT log_cluster_id, AVG(embedding) FROM log 
                WHERE embedding IS NOT NULL AND log_cluster_id = (SELECT log_cluster_id FROM log WHERE id = :id)
                GROUP BY log_cluster_id
                ON CONFLICT (log_cluster_id) DO UPDATE SET avg_embedding = EXCLUDED.avg_embedding
            """), {"id": log_id})
        conn.commit()

        # Ergebnisse auslesen
        result = conn.execute(text("SELECT id, log_cluster_id FROM log ORDER BY id")).fetchall()
        pgvector_labels = [row[1] if row[1] is not None else -1 for row in result]

    all_results['pgvector']['ari'].append(adjusted_rand_score(ground_truth_shuffled, pgvector_labels))
    all_results['pgvector']['v_measure'].append(v_measure_score(ground_truth_shuffled, pgvector_labels))
    all_results['pgvector']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, pgvector_labels))
    all_results['pgvector']['completeness'].append(completeness_score(ground_truth_shuffled, pgvector_labels))

    # ===== MINHASH LSH =====
    def _mh_tokenize(log_line, n=MINHASH_NGRAM_SIZE):
        words = log_line.split()
        if len(words) < n:
            return set(words) if words else {log_line}
        return set(' '.join(words[i:i+n]) for i in range(len(words) - n + 1))

    run_minhashes = []
    for log in logs_shuffled:
        m = MinHash(num_perm=MINHASH_NUM_PERM)
        for shingle in _mh_tokenize(log):
            m.update(shingle.encode('utf8'))
        run_minhashes.append(m)

    run_lsh = MinHashLSH(threshold=MINHASH_THRESHOLD, num_perm=MINHASH_NUM_PERM)
    for i, m in enumerate(run_minhashes):
        run_lsh.insert(str(i), m)

    _par = list(range(len(logs_shuffled)))

    def _find(x):
        while _par[x] != x:
            _par[x] = _par[_par[x]]
            x = _par[x]
        return x

    def _union(a, b):
        ra, rb = _find(a), _find(b)
        if ra != rb:
            _par[ra] = rb

    for i, m in enumerate(run_minhashes):
        for nb in run_lsh.query(m):
            _union(i, int(nb))

    r2c = {}
    mh_labels = []
    nxt = 0
    for i in range(len(logs_shuffled)):
        root = _find(i)
        if root not in r2c:
            r2c[root] = nxt
            nxt += 1
        mh_labels.append(r2c[root])

    all_results['MinHash LSH']['ari'].append(adjusted_rand_score(ground_truth_shuffled, mh_labels))
    all_results['MinHash LSH']['v_measure'].append(v_measure_score(ground_truth_shuffled, mh_labels))
    all_results['MinHash LSH']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, mh_labels))
    all_results['MinHash LSH']['completeness'].append(completeness_score(ground_truth_shuffled, mh_labels))


    # ===== BRAIN =====
    _brain_st = _dt.datetime.now()
    _brain_df_in = pd.DataFrame(index=range(len(logs_shuffled)))
    _brain_df_out, _ = Brain.parse(
        logs_shuffled,
        [r'((\d+\.){3}\d+,?)+', r'/.+?\s ', r'\d+'],
        'OpenStack', 5, [], _brain_st, efficiency=False, df_input=_brain_df_in)
    _eids = _brain_df_out['EventId'].tolist()
    _eid_map = {eid: idx for idx, eid in enumerate(dict.fromkeys(_eids))}
    brain_labels = [_eid_map[eid] for eid in _eids]

    all_results['Brain']['ari'].append(adjusted_rand_score(ground_truth_shuffled, brain_labels))
    all_results['Brain']['v_measure'].append(v_measure_score(ground_truth_shuffled, brain_labels))
    all_results['Brain']['homogeneity'].append(homogeneity_score(ground_truth_shuffled, brain_labels))
    all_results['Brain']['completeness'].append(completeness_score(ground_truth_shuffled, brain_labels))

    print(f"   ✅ Durchlauf {run_idx + 1} abgeschlossen")

# ===== DURCHSCHNITTSWERTE BERECHNEN =====
print(f"\n\n{'='*70}")
print("DURCHSCHNITTLICHE ERGEBNISSE ÜBER 5 DURCHLÄUFE")
print(f"{'='*70}\n")

summary_data = []

for alg in ['K-Means', 'DBSCAN', 'Drain3', 'pgvector', 'MinHash LSH', 'Brain']:
    ari_mean = np.mean(all_results[alg]['ari']) * 100
    ari_std = np.std(all_results[alg]['ari']) * 100
    v_mean = np.mean(all_results[alg]['v_measure']) * 100
    v_std = np.std(all_results[alg]['v_measure']) * 100
    hom_mean = np.mean(all_results[alg]['homogeneity']) * 100
    hom_std = np.std(all_results[alg]['homogeneity']) * 100
    comp_mean = np.mean(all_results[alg]['completeness']) * 100
    comp_std = np.std(all_results[alg]['completeness']) * 100

    summary_data.append({
        'Algorithmus': alg,
        'ARI (%)': f"{ari_mean:.3f} ± {ari_std:.3f}",
        'V-Measure (%)': f"{v_mean:.3f} ± {v_std:.3f}",
        'Homogenität (%)': f"{hom_mean:.3f} ± {hom_std:.3f}",
        'Vollständigkeit (%)': f"{comp_mean:.3f} ± {comp_std:.3f}"
    })

    print(f"📊 {alg}:")
    print(f"   ARI:            {ari_mean:6.3f}% ± {ari_std:.3f}%")
    print(f"   V-Measure:      {v_mean:6.3f}% ± {v_std:.3f}%")
    print(f"   Homogenität:    {hom_mean:6.3f}% ± {hom_std:.3f}%")
    print(f"   Vollständigkeit:{comp_mean:6.3f}% ± {comp_std:.3f}%")
    print()

print(f"{'='*70}")

# Ergebnis-Tabelle
df_summary = pd.DataFrame(summary_data)
print("\n📋 Zusammenfassung als Tabelle:")
df_summary
df_summary.to_csv("./results/multirun_results.csv",index=False)

