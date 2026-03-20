import express from 'express';
import cors from 'cors';
import { pool } from './db.js';
import dotenv from 'dotenv';
import dns from "node:dns";
import bcrypt from 'bcryptjs';
import { titleCaseNome, normalizarEmail, somenteNumeros } from './utils.js';
import crypto from 'node:crypto';

import fs from "node:fs";
import path from "node:path";
import multer from "multer";
import fetch from 'node-fetch';
import cron from 'node-cron';

dns.setDefaultResultOrder("ipv4first");
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// =====================
// Middleware base
// =====================
app.use(cors({ origin: true }));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// =====================
// Fotos de usuário (volume /anexos/foto-usuario)
// =====================
const DIRETORIO_VOLUME_anexos = process.env.RAILWAY_VOLUME_MOUNT_PATH || "/anexos";
const PASTA_FOTO_USUARIO = path.join(DIRETORIO_VOLUME_anexos, "foto-usuario");

fs.mkdirSync(PASTA_FOTO_USUARIO, { recursive: true });

app.use("/anexos/foto-usuario", express.static(PASTA_FOTO_USUARIO));

// =====================
// Ajuste timezone MySQL
// =====================
(async () => {
  try {
    await pool.query("SET time_zone = '-03:00'");
    console.log('MySQL time_zone ajustado para -03:00');
  } catch (e) {
    console.error('Falha ao setar time_zone:', e);
  }
})();

// =====================
// Rotas de saúde / debug
// =====================
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'API online' });
});

app.get('/health', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT 1 as test');
    res.json({
      status: 'OK',
      mysql: 'Connected!',
      test: rows[0].test
    });
  } catch (err) {
    console.error('MySQL erro:', err.message);
    res.status(500).json({
      error: 'MySQL falhou',
      details: err.message,
      vars: {
        host: !!process.env.MYSQLHOST,
        port: !!process.env.MYSQLPORT,
        user: !!process.env.MYSQLUSER,
        db: !!process.env.MYSQLDATABASE
      }
    });
  }
});

app.get('/debug', (req, res) => {
  res.json({
    mysqlVars: {
      host: process.env.MYSQLHOST ? 'OK' : 'MISSING',
      port: process.env.MYSQLPORT,
      user: process.env.MYSQLUSER ? 'OK' : 'MISSING',
      pass: process.env.MYSQLPASSWORD ? 'OK' : 'MISSING',
      db: process.env.MYSQLDATABASE ? 'OK' : 'MISSING'
    }
  });
});

// =====================
// API Login
// =====================
app.post('/api/login', async (req, res) => {
  try {
    const email = normalizarEmail(req.body?.email);
    const senha = req.body?.senha?.toString();

    if (!email || !senha) {
      return res.status(400).json({
        success: false,
        message: 'Email e senha são obrigatórios.'
      });
    }

    const [rows] = await pool.query(
      `SELECT
         ID,
         EMAIL,
         NOME,
         SENHA,
         STATUS,
         MUST_CHANGE_PASSWORD,
         FOTO,
         DATA_NASCIMENTO,
         FOTO, 
         PERFIL
       FROM SF_USUARIO
       WHERE EMAIL = ?
       LIMIT 1`,
      [email]
    );

    if (!rows.length) {
      return res.status(401).json({
        success: false,
        message: 'Email ou senha inválidos.'
      });
    }

    const u = rows[0];

    if (String(u.STATUS).trim() !== 'Ativo') {
      return res.status(403).json({
        success: false,
        message: 'Usuário desativado.'
      });
    }

    const ok = await bcrypt.compare(senha, u.SENHA);
    if (!ok) {
      return res.status(401).json({
        success: false,
        message: 'Email ou senha inválidos.'
      });
    }

    return res.json({
      success: true,
      email: u.EMAIL,
      nome: u.NOME,
      id: u.ID,
      mustChangePassword: Number(u.MUST_CHANGE_PASSWORD) === 1,
      foto: u.FOTO || '',
      dataNascimento: u.DATA_NASCIMENTO || null,
      perfil: u.PERFIL
    });
  } catch (err) {
    console.error('Erro /api/login:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro interno.',
      error: err.message
    });
  }
});


app.post('/api/usuarios/primeiro-acesso/senha', async (req, res) => {
  try {
    const email = normalizarEmail(req.body?.email);
    const newPassword = (req.body?.newPassword || '').toString();

    if (!email || !newPassword) return res.status(400).json({ success: false, message: 'Dados incompletos.' });
    if (newPassword.length < 6) return res.status(400).json({ success: false, message: 'Senha mínima: 6 caracteres.' });

    const hash = await bcrypt.hash(newPassword, 12);

    await pool.query(
      `UPDATE SF_USUARIO
          SET SENHA = ?, MUST_CHANGE_PASSWORD = 0
        WHERE EMAIL = ?`,
      [hash, email]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('Erro primeiro acesso senha:', err);
    return res.status(500).json({ success: false, message: 'Erro ao atualizar senha.', error: err.message });
  }
});


// =====================
// Aniversariantes do mes
// =====================
app.get('/api/aniversariantes/mes', async (req, res) => {
  try {
    console.log('[ANIVERSARIANTES_MES] Iniciando busca dos aniversariantes do mês...');

    const result = await pool.query(`
      SELECT
        ID,
        NOME,
        SETOR,
        LOCAL_TRABALHO,
        FOTO,
        DATA_NASCIMENTO
      FROM SF_USUARIO
      WHERE
        STATUS = 'Ativo'
        AND DATA_NASCIMENTO IS NOT NULL
        AND MONTH(DATA_NASCIMENTO) = MONTH(CURDATE())
      ORDER BY DAY(DATA_NASCIMENTO) ASC, NOME ASC
    `);

    console.log('[ANIVERSARIANTES_MES] Resultado bruto:', result);

    const rows = Array.isArray(result?.[0]) ? result[0] : result;

    console.log('[ANIVERSARIANTES_MES] Linhas extraídas:', rows);
    console.log('[ANIVERSARIANTES_MES] Total de registros encontrados:', rows.length);

    const hoje = new Date();
    const diaHoje = hoje.getDate();
    const mesHoje = hoje.getMonth() + 1;

    console.log('[ANIVERSARIANTES_MES] Hoje é:', {
      diaHoje,
      mesHoje,
      dataIso: hoje.toISOString()
    });

    const items = rows.map((r, index) => {
      const dt = r.DATA_NASCIMENTO ? new Date(r.DATA_NASCIMENTO) : null;
      const dia = dt && !Number.isNaN(dt.getTime()) ? dt.getDate() : null;
      const mes = dt && !Number.isNaN(dt.getTime()) ? dt.getMonth() + 1 : null;
      const aniversarioHoje = dia === diaHoje && mes === mesHoje;

      const item = {
        id: r.ID,
        nome: r.NOME || '',
        setor: r.SETOR || '',
        localTrabalho: r.LOCAL_TRABALHO || '',
        foto: r.FOTO || '',
        dataNascimento: r.DATA_NASCIMENTO || null,
        aniversarioHoje
      };

      console.log(`[ANIVERSARIANTES_MES] Registro ${index + 1}:`, {
        bruto: r,
        convertido: item,
        diaExtraido: dia,
        mesExtraido: mes
      });

      return item;
    });

    console.log('[ANIVERSARIANTES_MES] Items finais enviados ao front:', items);

    return res.json({
      success: true,
      items
    });
  } catch (err) {
    console.error('[ANIVERSARIANTES_MES] Erro na rota:', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      message: 'Erro ao listar aniversariantes do mês.',
      error: err.message
    });
  }
});


// =====================
// Agendamentos - Sala
// =====================
app.post('/api/agendamentos/sala/verificar', async (req, res) => {
  try {
    const { sala, inicio, fim } = req.body;

    if (!sala || !inicio || !fim) {
      return res.status(400).json({ success: false, message: 'sala, inicio e fim são obrigatórios.' });
    }

    const ini = new Date(inicio);
    const end = new Date(fim);
    if (!(end > ini)) {
      return res.status(400).json({ success: false, message: 'fim deve ser maior que inicio.' });
    }

    const [rows] = await pool.query(
      `
      SELECT
        sala,
        inicio,
        fim,
        motivo,
        usuario_agendamento,
        data_agendamento
      FROM SF_AGENDAMENTO
      WHERE sala = ?
        AND status = 'Agendado'
        AND inicio < ?
        AND fim > ?
      ORDER BY inicio ASC
      LIMIT 1
      `,
      [sala, fim, inicio]
    );

    if (rows.length > 0) {
      return res.json({
        success: true,
        conflito: true,
        message: 'Existe conflito de agendamento.',
        conflitoDetalhe: rows[0]
      });
    }

    return res.json({ success: true, conflito: false, message: 'Sem conflito.' });
  } catch (err) {
    console.error('Erro /api/agendamentos/sala/verificar:', err);
    return res.status(500).json({ success: false, message: 'Erro interno no servidor.', error: err.message });
  }
});

app.post('/api/agendamentos/sala', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const { sala, inicio, fim, motivo, usuario, participantes } = req.body;

    if (!sala || !inicio || !fim || !motivo || !usuario) {
      return res.status(400).json({
        success: false,
        message: 'sala, inicio, fim, motivo e usuario são obrigatórios.'
      });
    }

    const ini = new Date(inicio);
    const end = new Date(fim);
    if (!(end > ini)) {
      return res.status(400).json({ success: false, message: 'fim deve ser maior que inicio.' });
    }

    const ids = Array.isArray(participantes)
      ? participantes.map(Number).filter(Number.isFinite)
      : [];

    await conn.beginTransaction();

    const [ins] = await conn.query(
      `INSERT INTO SF_AGENDAMENTO (sala, inicio, fim, motivo, usuario_agendamento, status, data_agendamento)
       VALUES (?, ?, ?, ?, ?, 'Agendado', NOW())`,
      [sala, inicio, fim, motivo, usuario]
    );

    const idAgendamento = ins.insertId;

    let convidados = [];
    if (ids.length) {
      const [u] = await conn.query(
        `SELECT id, nome, email
           FROM SF_USUARIO
          WHERE id IN (?)
            AND email IS NOT NULL AND email <> ''`,
        [ids]
      );
      convidados = u;
    }

    for (const p of convidados) {
      await conn.query(
        `INSERT INTO SF_AGENDAMENTO_PARTICIPANTE (id_agendamento, id_usuario, nome, email)
         VALUES (?, ?, ?, ?)`,
        [idAgendamento, p.id, p.nome, p.email]
      );
    }

    for (const p of convidados) {
      const uid = `${idAgendamento}-${p.id}@sociedadefranciosi`;

      await conn.query(
        `INSERT INTO SF_EMAIL_QUEUE
          (tipo, status, tentativas, max_tentativas,
           id_agendamento, id_usuario, email, nome,
           sala, inicio, fim, motivo, uid, sequence,
           created_at)
         VALUES
          ('CONVITE_SALA', 'PENDENTE', 0, 5,
           ?, ?, ?, ?,
           ?, ?, ?, ?, ?, 0,
           NOW())`,
        [
          idAgendamento, p.id, p.email, p.nome,
          sala, inicio, fim, motivo, uid
        ]
      );
    }

    await conn.commit();

    if (!convidados.length) {
      return res.json({
        success: true,
        message: 'Agendamento salvo (sem participantes selecionados).',
        id: idAgendamento,
        filaEmail: { total: 0, enfileirados: 0 }
      });
    }

    return res.json({
      success: true,
      message: 'Agendamento salvo. Convites enfileirados para envio.',
      id: idAgendamento,
      filaEmail: { total: convidados.length, enfileirados: convidados.length }
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar agendamento.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.get('/api/agendamentos/sala/dia', async (req, res) => {
  try {
    const { data } = req.query;
    const [rows] = await pool.query(
      `
      SELECT
        id,
        sala,
        inicio,
        fim,
        motivo,
        usuario_agendamento,
        data_agendamento
      FROM SF_AGENDAMENTO
      WHERE status = 'Agendado'
        AND DATE(inicio) = COALESCE(?, CURDATE())
      ORDER BY inicio ASC
      `,
      [data || null]
    );

    return res.json({ success: true, items: rows });
  } catch (err) {
    console.error('Erro /api/agendamentos/sala/dia:', err);
    res.status(500).json({ success: false, message: 'Erro interno no servidor.', error: err.message });
  }
});

app.delete('/api/cancelar-agendamentos/sala/:id', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const id = Number(req.params.id);

    const usuarioSolicitante =
      String(req.headers['x-usuario'] || req.headers['x-user'] || '').trim();

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do agendamento inválido.'
      });
    }

    if (!usuarioSolicitante) {
      return res.status(400).json({
        success: false,
        message: 'Usuário solicitante é obrigatório.'
      });
    }

    await conn.beginTransaction();

    const [agRows] = await conn.query(
      `SELECT
         id,
         sala,
         inicio,
         fim,
         motivo,
         usuario_agendamento,
         status
       FROM SF_AGENDAMENTO
       WHERE id = ?
       LIMIT 1`,
      [id]
    );

    if (!agRows.length) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Agendamento não encontrado.'
      });
    }

    const ag = agRows[0];

    if (ag.status !== 'Agendado') {
      await conn.rollback();
      return res.status(409).json({
        success: false,
        message: 'Este agendamento não está mais como Agendado.'
      });
    }

    const [usuarioRows] = await conn.query(
      `SELECT
         u.ID,
         u.NOME,
         u.PERFIL,
         p.excluir_agendamento_sala_reuniao
       FROM SF_USUARIO u
       LEFT JOIN SF_PERFIL p
         ON p.NOME = u.PERFIL
       WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
       LIMIT 1`,
      [usuarioSolicitante]
    );

    if (!usuarioRows.length) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Usuário solicitante não encontrado ou sem perfil válido.'
      });
    }

    const usuarioDb = usuarioRows[0];

    const ehCriador =
      String(ag.usuario_agendamento || '').trim().toUpperCase() ===
      String(usuarioSolicitante || '').trim().toUpperCase();

    const ehMasterExclusao =
      Number(usuarioDb.excluir_agendamento_sala_reuniao) === 1;

    if (!ehCriador && !ehMasterExclusao) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para excluir este agendamento.'
      });
    }

    const [upd] = await conn.query(
      `UPDATE SF_AGENDAMENTO
          SET status = 'Cancelado',
              usuario_cancelamento = ?,
              data_cancelamento = NOW()
        WHERE id = ?
          AND status = 'Agendado'`,
      [usuarioSolicitante, id]
    );

    if (upd.affectedRows === 0) {
      await conn.rollback();
      return res.status(409).json({
        success: false,
        message: 'Não foi possível cancelar (agendamento já alterado).'
      });
    }

    const [parts] = await conn.query(
      `SELECT
         id_usuario,
         nome,
         email
       FROM SF_AGENDAMENTO_PARTICIPANTE
       WHERE id_agendamento = ?
         AND email IS NOT NULL
         AND email <> ''`,
      [id]
    );

    for (const p of parts) {
      const uid = `${ag.id}-${p.id_usuario}@sociedadefranciosi`;

      await conn.query(
        `INSERT INTO SF_EMAIL_QUEUE
          (tipo, status, tentativas, max_tentativas,
           id_agendamento, id_usuario, email, nome,
           sala, inicio, fim, motivo, uid, sequence,
           created_at)
         VALUES
          ('CANCELAR_SALA', 'PENDENTE', 0, 5,
           ?, ?, ?, ?,
           ?, ?, ?, ?, ?, 1,
           NOW())`,
        [
          ag.id,
          p.id_usuario,
          p.email,
          p.nome,
          ag.sala,
          ag.inicio,
          ag.fim,
          ag.motivo,
          uid
        ]
      );
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Agendamento cancelado com sucesso. Cancelamentos enfileirados para envio.',
      cancelEmails: {
        total: parts.length,
        enfileirados: parts.length
      }
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro DELETE /api/cancelar-agendamentos/sala/:id:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro interno no servidor.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});


// =====================
// Usuários / Setores
// =====================

function soNumeros(v) {
  return String(v ?? '').replace(/\D+/g, '');
}

function texto(v) {
  return String(v ?? '').trim();
}

function normalizarEmailNullable(v) {
  const s = String(v ?? '').trim().toLowerCase();
  return s || null;
}

function nullable(v) {
  const s = String(v ?? '').trim();
  return s || null;
}

function nullableDate(v) {
  const s = String(v ?? '').trim();
  if (!s) return null;
  return s.slice(0, 10);
}


app.get('/api/gestao-usuarios-centro-custo', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ID, NOME
         FROM SF_CENTRO_CUSTO
        WHERE NOME IS NOT NULL
          AND NOME <> ''
        ORDER BY NOME ASC`
    );

    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar locais de trabalho.',
      error: err.message,
    });
  }
});

app.post('/api/gestao-usuarios-centro-custo', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome do local de trabalho é obrigatório.',
      });
    }

    const [r] = await pool.query(
      `INSERT INTO SF_CENTRO_CUSTO (NOME)
       VALUES (?)`,
      [nome]
    );

    res.status(201).json({
      success: true,
      item: {
        id: r.insertId,
        nome,
      },
    });
  } catch (err) {
    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Já existe um local de trabalho com esse nome.',
      });
    }

    res.status(500).json({
      success: false,
      message: 'Erro ao adicionar local de trabalho.',
      error: err.message,
    });
  }
});




app.get('/api/usuarios', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, nome, email, setor
         FROM SF_USUARIO
        WHERE email IS NOT NULL AND email <> ''
        ORDER BY nome ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao listar usuários.', error: err.message });
  }
});

app.patch('/api/gestao-usuarios/:id(\\d+)/status', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const status = (req.body?.status || '').toString().trim();

    if (!status) return res.status(400).json({ success: false, message: 'Status é obrigatório.' });

    const [r] = await pool.query(`UPDATE SF_USUARIO SET STATUS = ? WHERE ID = ?`, [status, id]);
    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao alterar status.', error: err.message });
  }
});

app.delete('/api/gestao-usuarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const [r] = await pool.query(`DELETE FROM SF_USUARIO WHERE ID = ?`, [id]);
    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao excluir usuário.', error: err.message });
  }
});

app.patch('/api/gestao-usuarios/:id(\\d+)/senha', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const senhaAtual = (req.body?.senhaAtual || '').toString();
    const novaSenha = (req.body?.novaSenha || '').toString();

    if (!senhaAtual) return res.status(400).json({ success: false, message: 'senhaAtual é obrigatória.' });
    if (!novaSenha || novaSenha.length < 6) return res.status(400).json({ success: false, message: 'novaSenha inválida (mínimo 6).' });

    const [rows] = await pool.query(`SELECT SENHA FROM SF_USUARIO WHERE ID = ?`, [id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });

    const ok = await bcrypt.compare(senhaAtual, rows[0].SENHA);
    if (!ok) return res.status(401).json({ success: false, message: 'Senha atual incorreta.' });

    const novoHash = await bcrypt.hash(novaSenha, 12);
    await pool.query(`UPDATE SF_USUARIO SET SENHA = ? WHERE ID = ?`, [novoHash, id]);

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao trocar senha.', error: err.message });
  }
});

app.patch('/api/gestao-usuarios/:id(\\d+)/senha-reset', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const novaSenha = (req.body?.novaSenha || '').toString();

    if (!novaSenha || novaSenha.length < 6) return res.status(400).json({ success: false, message: 'novaSenha inválida (mínimo 6).' });

    const novoHash = await bcrypt.hash(novaSenha, 12);

    const [r] = await pool.query(`UPDATE SF_USUARIO SET SENHA = ? WHERE ID = ?`, [novoHash, id]);
    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao resetar senha.', error: err.message });
  }
});

app.get('/api/gestao-usuarios', async (req, res) => {
  try {
    const busca = texto(req.query?.q);
    let sql = `
      SELECT
        id, nome, EMAIL, telefone, perfil, status, setor,
        FUNCAO, DATA_ADMISSAO, CENTRO_CUSTO, LOCAL_TRABALHO,
        CPF, RG, CNH, CNH_CATEGORIA, DATA_NASCIMENTO, ESTADO_CIVIL,
        TELEFONE_PESSOAL, EMAIL_PESSOAL, CNH_VALIDADE, CNH_ARQUIVO, FOTO,
        APELIDO, NUMERO_CALCADO, TAMANHO_CAMISA, TAMANHO_CALCA, SEXO,
        TEM_FILHOS, QUANTIDADE_FILHOS, FILHOS
      FROM SF_USUARIO
    `;
    const params = [];

    if (busca) {
      sql += ` WHERE nome LIKE ? OR EMAIL LIKE ? OR perfil LIKE ? OR setor LIKE ? `;
      const like = `%${busca}%`;
      params.push(like, like, like, like);
    }

    sql += ' ORDER BY nome ASC';

    const rows = await pool.query(sql, params);
    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar usuários.',
      error: err.message
    });
  }
});



app.get('/api/gestao-usuarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const rows = await pool.query(`
      SELECT
        id, nome, EMAIL, telefone, perfil, status, setor,
        FUNCAO, DATA_ADMISSAO, CENTRO_CUSTO, LOCAL_TRABALHO,
        CPF, RG, CNH, CNH_CATEGORIA, DATA_NASCIMENTO, ESTADO_CIVIL,
        TELEFONE_PESSOAL, EMAIL_PESSOAL, CNH_VALIDADE, CNH_ARQUIVO, FOTO,
        APELIDO, NUMERO_CALCADO, TAMANHO_CAMISA, TAMANHO_CALCA, SEXO,
        TEM_FILHOS, QUANTIDADE_FILHOS, FILHOS
      FROM SF_USUARIO
      WHERE id = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    return res.json({ success: true, item: rows[0] });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar usuário.',
      error: err.message
    });
  }
});


app.post('/api/gestao-usuarios-adicionar', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);
    const email = normalizarEmail(req.body?.email);
    const senha = texto(req.body?.senha);
    const telefone = somenteNumeros(req.body?.telefone);
    const perfil = texto(req.body?.perfil);
    const setor = titleCaseNome(req.body?.setor);
    const funcao = texto(req.body?.funcao);
    const dataAdmissao = nullableDate(req.body?.dataadmissao);
    const centroCusto = titleCaseNome(req.body?.localtrabalho || req.body?.centrocusto);
    const localTrabalho = titleCaseNome(req.body?.unidadetrabalho);
    const status = texto(req.body?.status || 'Ativo');

    const cpf = somenteNumeros(req.body?.cpf);
    const rg = texto(req.body?.rg);
    const cnh = texto(req.body?.cnh);
    const cnhCategoria = texto(req.body?.cnhcategoria)?.toUpperCase() || null;
    const cnhValidade = nullableDate(req.body?.cnhvalidade);
    const cnhArquivo = texto(req.body?.cnharquivo);
    const dataNascimento = nullableDate(req.body?.datanascimento);
    const estadoCivil = texto(req.body?.estadocivil);
    const telefonePessoal = somenteNumeros(req.body?.telefonepessoal);
    const emailPessoal = req.body?.emailpessoal ? normalizarEmail(req.body?.emailpessoal) : null;
    const foto = texto(req.body?.foto);

    const apelido = texto(req.body?.apelido);
    const numeroCalcado = String(req.body?.numerocalcado ?? '').trim() !== '' ? Number(req.body.numerocalcado) : null;
    const tamanhoCamisa = texto(req.body?.tamanhocamisa)?.toUpperCase() || null;
    const tamanhoCalca = texto(req.body?.tamanhocalca);
    const sexo = texto(req.body?.sexo)?.toUpperCase() || null;
    const temFilhos = texto(req.body?.temfilhos)?.toUpperCase() || 'NÃO';
    const quantidadeFilhos = temFilhos === 'SIM' && String(req.body?.quantidadefilhos ?? '').trim() !== ''
      ? Number(req.body.quantidadefilhos)
      : null;
    const filhos = temFilhos === 'SIM' && Array.isArray(req.body?.filhos)
      ? JSON.stringify(req.body.filhos)
      : null;

    if (!nome || !email || !senha || !perfil || !setor || !status) {
      return res.status(400).json({
        success: false,
        message: 'Nome, e-mail, senha, perfil, setor e status são obrigatórios.'
      });
    }

    if (senha.length < 6) {
      return res.status(400).json({
        success: false,
        message: 'Senha deve ter no mínimo 6 caracteres.'
      });
    }

    const emailExistente = await pool.query(
      'SELECT id FROM SF_USUARIO WHERE EMAIL = ? LIMIT 1',
      [email]
    );

    if (emailExistente.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Já existe usuário com este e-mail.'
      });
    }

    const senhaHash = await bcrypt.hash(senha, 12);

    const result = await pool.query(`
      INSERT INTO SF_USUARIO (
        nome, EMAIL, senha, telefone, perfil, status, setor,
        FUNCAO, DATA_ADMISSAO, CENTRO_CUSTO, LOCAL_TRABALHO,
        CPF, RG, CNH, CNH_CATEGORIA, DATA_NASCIMENTO, ESTADO_CIVIL,
        TELEFONE_PESSOAL, EMAIL_PESSOAL, CNH_VALIDADE, CNH_ARQUIVO, FOTO,
        APELIDO, NUMERO_CALCADO, TAMANHO_CAMISA, TAMANHO_CALCA, SEXO,
        TEM_FILHOS, QUANTIDADE_FILHOS, FILHOS,
        MUST_CHANGE_PASSWORD
      ) VALUES (
        ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?,
        1
      )
    `, [
      nome,
      email,
      senhaHash,
      telefone || null,
      perfil || null,
      status,
      setor || null,

      funcao || null,
      dataAdmissao,
      centroCusto || null,
      localTrabalho || null,

      cpf || null,
      rg || null,
      cnh || null,
      cnhCategoria || null,
      dataNascimento,
      estadoCivil || null,

      telefonePessoal || null,
      emailPessoal || null,
      cnhValidade,
      cnhArquivo || null,
      foto || null,

      apelido || null,
      Number.isFinite(numeroCalcado) ? numeroCalcado : null,
      tamanhoCamisa || null,
      tamanhoCalca || null,
      sexo || null,

      temFilhos,
      Number.isFinite(quantidadeFilhos) ? quantidadeFilhos : null,
      filhos
    ]);

    return res.status(201).json({
      success: true,
      item: { id: result.insertId, nome, email }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar usuário.',
      error: err.message
    });
  }
});


app.put('/api/gestao-usuarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const nome = titleCaseNome(req.body?.nome);
    const email = normalizarEmail(req.body?.email);
    const telefone = somenteNumeros(req.body?.telefone);
    const perfil = texto(req.body?.perfil);
    const setor = titleCaseNome(req.body?.setor);
    const funcao = texto(req.body?.funcao);
    const dataAdmissao = nullableDate(req.body?.dataadmissao);
    const centroCusto = titleCaseNome(req.body?.localtrabalho || req.body?.centrocusto);
    const localTrabalho = titleCaseNome(req.body?.unidadetrabalho);
    const status = texto(req.body?.status || 'Ativo');

    const cpf = somenteNumeros(req.body?.cpf);
    const rg = texto(req.body?.rg);
    const cnh = texto(req.body?.cnh);
    const cnhCategoria = texto(req.body?.cnhcategoria)?.toUpperCase() || null;
    const cnhValidade = nullableDate(req.body?.cnhvalidade);
    const cnhArquivo = req.body?.cnharquivo;
    const dataNascimento = nullableDate(req.body?.datanascimento);
    const estadoCivil = texto(req.body?.estadocivil);
    const telefonePessoal = somenteNumeros(req.body?.telefonepessoal);
    const emailPessoal = texto(req.body?.emailpessoal) ? normalizarEmail(req.body?.emailpessoal) : null;
    const foto = req.body?.foto;

    const apelido = texto(req.body?.apelido);
    const numeroCalcado = String(req.body?.numerocalcado ?? '').trim() !== '' ? Number(req.body.numerocalcado) : null;
    const tamanhoCamisa = texto(req.body?.tamanhocamisa)?.toUpperCase() || null;
    const tamanhoCalca = texto(req.body?.tamanhocalca);
    const sexo = texto(req.body?.sexo)?.toUpperCase() || null;
    const temFilhos = texto(req.body?.temfilhos)?.toUpperCase() || 'NÃO';
    const quantidadeFilhos = temFilhos === 'SIM' && String(req.body?.quantidadefilhos ?? '').trim() !== ''
      ? Number(req.body.quantidadefilhos)
      : null;
    const filhos = temFilhos === 'SIM' && Array.isArray(req.body?.filhos)
      ? JSON.stringify(req.body.filhos)
      : null;

    if (!nome || !email || !perfil || !setor || !status) {
      return res.status(400).json({
        success: false,
        message: 'Nome, e-mail, perfil, setor e status são obrigatórios.'
      });
    }

    const rows = await pool.query(
      'SELECT id, FOTO, CNH_ARQUIVO FROM SF_USUARIO WHERE id = ? LIMIT 1',
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const atual = rows[0];

    const emailExistente = await pool.query(
      'SELECT id FROM SF_USUARIO WHERE EMAIL = ? AND id <> ? LIMIT 1',
      [email, id]
    );

    if (emailExistente.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro usuário com este e-mail.'
      });
    }

    let fotoFinal = atual.FOTO ?? null;
    if (foto === null) fotoFinal = null;
    else if (typeof foto === 'string' && foto.trim() !== '') fotoFinal = foto.trim();

    let cnhArquivoFinal = atual.CNH_ARQUIVO ?? null;
    if (cnhArquivo === null) cnhArquivoFinal = null;
    else if (typeof cnhArquivo === 'string' && cnhArquivo.trim() !== '') cnhArquivoFinal = cnhArquivo.trim();

    const result = await pool.query(`
      UPDATE SF_USUARIO SET
        nome = ?,
        EMAIL = ?,
        telefone = ?,
        perfil = ?,
        status = ?,
        setor = ?,
        FUNCAO = ?,
        DATA_ADMISSAO = ?,
        CENTRO_CUSTO = ?,
        LOCAL_TRABALHO = ?,
        CPF = ?,
        RG = ?,
        CNH = ?,
        CNH_CATEGORIA = ?,
        DATA_NASCIMENTO = ?,
        ESTADO_CIVIL = ?,
        TELEFONE_PESSOAL = ?,
        EMAIL_PESSOAL = ?,
        CNH_VALIDADE = ?,
        CNH_ARQUIVO = ?,
        FOTO = ?,
        APELIDO = ?,
        NUMERO_CALCADO = ?,
        TAMANHO_CAMISA = ?,
        TAMANHO_CALCA = ?,
        SEXO = ?,
        TEM_FILHOS = ?,
        QUANTIDADE_FILHOS = ?,
        FILHOS = ?
      WHERE id = ?
    `, [
      nome,
      email,
      telefone || null,
      perfil || null,
      status,
      setor || null,
      funcao || null,
      dataAdmissao,
      centroCusto || null,
      localTrabalho || null,
      cpf || null,
      rg || null,
      cnh || null,
      cnhCategoria || null,
      dataNascimento,
      estadoCivil || null,
      telefonePessoal || null,
      emailPessoal || null,
      cnhValidade,
      cnhArquivoFinal,
      fotoFinal,
      apelido || null,
      Number.isFinite(numeroCalcado) ? numeroCalcado : null,
      tamanhoCamisa || null,
      tamanhoCalca || null,
      sexo || null,
      temFilhos,
      Number.isFinite(quantidadeFilhos) ? quantidadeFilhos : null,
      filhos,
      id
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    return res.json({
      success: true,
      message: 'Usuário atualizado com sucesso.'
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar usuário.',
      error: err.message
    });
  }
});


app.get('/api/setores', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT DISTINCT nome
         FROM SF_SETOR
        WHERE nome IS NOT NULL AND nome <> ''
        ORDER BY nome ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao listar setores.', error: err.message });
  }
});

// =====================
// Gestão Usuários
// =====================
app.get('/api/gestao-usuarios-perfis', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ID, NOME
         FROM SF_PERFIL
        WHERE NOME IS NOT NULL AND NOME <> ''
        ORDER BY NOME ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao listar perfis.', error: err.message });
  }
});

app.get('/api/gestao-usuarios-setores', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ID, NOME
         FROM SF_SETOR
        WHERE NOME IS NOT NULL AND NOME <> ''
        ORDER BY NOME ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao listar setores.', error: err.message });
  }
});

app.post('/api/gestao-usuarios-setores', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);
    if (!nome) return res.status(400).json({ success: false, message: 'Nome do setor é obrigatório.' });

    const [r] = await pool.query(`INSERT INTO SF_SETOR (NOME) VALUES (?)`, [nome]);
    res.status(201).json({ success: true, item: { id: r.insertId, nome } });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Erro ao adicionar setor.', error: err.message });
  }
});

function ehImagem(mimetype) {
  return typeof mimetype === "string" && mimetype.startsWith("image/");
}

const storageFotoUsuario = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, PASTA_FOTO_USUARIO);
  },
  filename: (req, file, cb) => {
    const original = apenasNomeArquivoSeguroCNH(file.originalname || 'foto.jpg');
    const ext = path.extname(original) || '.jpg';
    const nomeSemExt = path.basename(original, ext);
    const unico = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${nomeSemExt}-${unico}${ext}`);
  },
});

const uploadFotoUsuario = multer({
  storage: storageFotoUsuario,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ehImagem(file.mimetype)) return cb(new Error('Apenas imagens são permitidas.'));
    cb(null, true);
  },
});

// Upload único da foto do usuário
app.post('/api/gestao-usuarios/foto', uploadFotoUsuario.single('foto'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Arquivo de foto não enviado.' });
    }

    return res.status(201).json({
      success: true,
      item: {
        name: req.file.filename,
        url: `/anexos/foto-usuario/${encodeURIComponent(req.file.filename)}`,
        size: req.file.size,
        mimetype: req.file.mimetype,
      },
    });
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message || 'Erro ao enviar foto.' });
  }
});

// Remover arquivo da foto do usuário
app.delete('/api/gestao-usuarios/foto/:nome', async (req, res) => {
  try {
    const nome = apenasNomeArquivoSeguroCNH(req.params.nome);
    if (!nome) return res.status(400).json({ success: false, message: 'Nome inválido.' });

    const base = path.resolve(PASTA_FOTO_USUARIO);
    const alvo = path.resolve(path.join(PASTA_FOTO_USUARIO, nome));
    if (!alvo.startsWith(base + path.sep)) {
      return res.status(400).json({ success: false, message: 'Caminho inválido.' });
    }

    await fs.promises.unlink(alvo);
    return res.json({ success: true, message: 'Foto removida.' });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ success: false, message: 'Arquivo não encontrado.' });
    }
    return res.status(500).json({ success: false, message: 'Erro ao remover foto.', error: err.message });
  }
});

app.get('/api/gestao-usuarios-funcoes', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT ID, NOME
      FROM SF_FUNCAO
      WHERE NOME IS NOT NULL AND NOME <> ''
      ORDER BY NOME ASC
    `);

    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar funções.',
      error: err.message
    });
  }
});

app.post('/api/gestao-usuarios-funcoes', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);
    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome da função é obrigatório.'
      });
    }

    const [r] = await pool.query(`INSERT INTO SF_FUNCAO (NOME) VALUES (?)`, [nome]);

    return res.status(201).json({
      success: true,
      item: { id: r.insertId, nome }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao adicionar função.',
      error: err.message
    });
  }
});

app.get('/api/gestao-usuarios-locais-trabalho', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT ID, NOME
      FROM SF_LOCAL_TRABALHO
      WHERE NOME IS NOT NULL AND NOME <> ''
      ORDER BY NOME ASC
    `);

    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar unidades de trabalho.',
      error: err.message
    });
  }
});

app.post('/api/gestao-usuarios-locais-trabalho', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);
    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome da unidade de trabalho é obrigatório.'
      });
    }

    const [r] = await pool.query(`INSERT INTO SF_LOCAL_TRABALHO (NOME) VALUES (?)`, [nome]);

    return res.status(201).json({
      success: true,
      item: { id: r.insertId, nome }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao adicionar unidade de trabalho.',
      error: err.message
    });
  }
});


// ======================================================
// GESTÃO DE USUÁRIOS - APOIO CNH
// ======================================================
const PASTA_CNH_USUARIO = path.join(DIRETORIO_VOLUME_anexos, 'cnh-usuario');
fs.mkdirSync(PASTA_CNH_USUARIO, { recursive: true });

app.use('/anexos/cnh-usuario', express.static(PASTA_CNH_USUARIO));


function apenasNomeArquivoSeguroCNH(nome) {
  return path.basename(String(nome || '')).replace(/[^\w.\-]/g, '');
}

function ehArquivoCnhValido(mimetype) {
  const tipos = [
    'application/pdf',
    'image/jpeg',
    'image/jpg',
    'image/png',
    'image/webp'
  ];
  return tipos.includes(String(mimetype || '').toLowerCase());
}

function extrairNomeArquivoDeUrlPossivel(url) {
  const s = texto(url);
  if (!s) return '';
  const semQuery = s.split('?')[0];
  return apenasNomeArquivoSeguroCNH(path.basename(semQuery));
}

async function apagarArquivoSeExistir(caminho) {
  try {
    await fs.promises.unlink(caminho);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

const storageCnhUsuario = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, PASTA_CNH_USUARIO);
  },
  filename: (req, file, cb) => {
    const original = apenasNomeArquivoSeguroCNH(file.originalname || 'cnh.pdf');
    const ext = path.extname(original) || '.pdf';
    const nomeSemExt = path.basename(original, ext);
    const unico = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${nomeSemExt}-${unico}${ext}`);
  },
});

const uploadCnhUsuario = multer({
  storage: storageCnhUsuario,
  limits: { fileSize: 15 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ehArquivoCnhValido(file.mimetype)) {
      return cb(new Error('Apenas PDF, JPG, JPEG, PNG ou WEBP são permitidos.'));
    }
    cb(null, true);
  },
});

app.post('/api/gestao-usuarios/cnh', uploadCnhUsuario.single('arquivo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Arquivo da CNH não enviado.' });
    }

    return res.status(201).json({
      success: true,
      item: {
        name: req.file.filename,
        url: `/anexos/cnh-usuario/${encodeURIComponent(req.file.filename)}`,
        size: req.file.size,
        mimetype: req.file.mimetype,
      },
    });
  } catch (err) {
    return res.status(400).json({
      success: false,
      message: err.message || 'Erro ao enviar arquivo da CNH.'
    });
  }
});

app.delete('/api/gestao-usuarios/cnh/:nome', async (req, res) => {
  try {
    const nome = apenasNomeArquivoSeguroCNH(req.params.nome);
    if (!nome) {
      return res.status(400).json({ success: false, message: 'Nome inválido.' });
    }

    const base = path.resolve(PASTA_CNH_USUARIO);
    const alvo = path.resolve(path.join(PASTA_CNH_USUARIO, nome));

    if (!alvo.startsWith(base + path.sep)) {
      return res.status(400).json({ success: false, message: 'Caminho inválido.' });
    }

    await fs.promises.unlink(alvo);
    return res.json({ success: true, message: 'Arquivo da CNH removido.' });
  } catch (err) {
    if (err.code === 'ENOENT') {
      return res.status(404).json({ success: false, message: 'Arquivo não encontrado.' });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao remover arquivo da CNH.',
      error: err.message
    });
  }
});



// =====================
// Password reset
// =====================

app.post('/api/password-reset/confirm', async (req, res) => {
  try {
    const email = normalizarEmail(req.body?.email);
    const token = (req.body?.token || '').toString().trim();
    const newPassword = (req.body?.newPassword || '').toString();

    if (!email || !token || !newPassword) {
      return res.status(400).json({ success: false, message: 'Dados incompletos.' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ success: false, message: 'Senha mínima: 6 caracteres.' });
    }

    const [rows] = await pool.query(
      `SELECT id, token_hash, expires_at
         FROM SF_PASSWORD_RESET
        WHERE email = ? AND token_hash IS NOT NULL
        ORDER BY id DESC
        LIMIT 1`,
      [email]
    );

    if (!rows.length) return res.status(400).json({ success: false, message: 'Token inválido.' });

    const r = rows[0];

    const [exp] = await pool.query(
      `SELECT (UTC_TIMESTAMP() <= ?) AS ok`,
      [r.expires_at]
    );
    if (!exp?.length || exp[0].ok !== 1) {
      return res.status(400).json({ success: false, message: 'Token expirado.' });
    }

    const ok = await bcrypt.compare(token, r.token_hash);
    if (!ok) return res.status(400).json({ success: false, message: 'Token inválido.' });

    const senhaHash = await bcrypt.hash(newPassword, 12);
    await pool.query(`UPDATE SF_USUARIO SET SENHA = ? WHERE EMAIL = ?`, [senhaHash, email]);

    return res.json({ success: true });
  } catch (err) {
    console.error('password-reset/confirm:', err);
    return res.status(500).json({ success: false, message: 'Erro ao atualizar senha.', error: err.message });
  }
});

app.post('/api/password-reset/verify', async (req, res) => {
  try {
    const email = normalizarEmail(req.body?.email);
    const code = (req.body?.code || '').toString().trim();
    if (!email || !code) return res.status(400).json({ success: false, message: 'Email e código são obrigatórios.' });

    const [rows] = await pool.query(
      `SELECT id, code_hash, expires_at, attempts
         FROM SF_PASSWORD_RESET
        WHERE email = ? AND used = 0
        ORDER BY id DESC
        LIMIT 1`,
      [email]
    );

    if (!rows.length) return res.status(400).json({ success: false, message: 'Código inválido ou já utilizado.' });

    const r = rows[0];

    const [exp] = await pool.query(
      `SELECT (UTC_TIMESTAMP() <= ?) AS ok`,
      [r.expires_at]
    );
    if (!exp?.length || exp[0].ok !== 1) {
      return res.status(400).json({ success: false, message: 'Código expirado.' });
    }

    const ok = await bcrypt.compare(code, r.code_hash);
    if (!ok) {
      await pool.query(`UPDATE SF_PASSWORD_RESET SET attempts = attempts + 1 WHERE id = ?`, [r.id]);
      return res.status(400).json({ success: false, message: 'Código inválido.' });
    }

    const token = crypto.randomBytes(24).toString('hex');
    const tokenHash = await bcrypt.hash(token, 10);

    await pool.query(
      `UPDATE SF_PASSWORD_RESET
          SET token_hash = ?, used = 1
        WHERE id = ?`,
      [tokenHash, r.id]
    );

    return res.json({ success: true, token });
  } catch (err) {
    console.error('password-reset/verify:', err);
    return res.status(500).json({ success: false, message: 'Erro ao verificar código.', error: err.message });
  }
});

app.post('/api/password-reset/request', async (req, res) => {
  try {
    const email = normalizarEmail(req.body?.email);
    if (!email) return res.status(400).json({ success: false, message: 'Email é obrigatório.' });

    const [u] = await pool.query(
      'SELECT ID, EMAIL, NOME FROM SF_USUARIO WHERE EMAIL = ? LIMIT 1',
      [email]
    );

    if (!u.length) return res.status(404).json({ success: false, message: 'Email não cadastrado.' });

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const codeHash = await bcrypt.hash(code, 10);
    const expiresMinutes = 10;

    await pool.query(
      `UPDATE SF_PASSWORD_RESET SET used = 1
        WHERE email = ? AND used = 0`,
      [email]
    );

    await pool.query(
      `INSERT INTO SF_PASSWORD_RESET (email, code_hash, expires_at, used, attempts, token_hash)
       VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? MINUTE), 0, 0, NULL)`,
      [email, codeHash, expiresMinutes]
    );

    const uid = `reset-${crypto.randomBytes(12).toString('hex')}@sociedadefranciosi`;

    await pool.query(
      `INSERT INTO SF_EMAIL_QUEUE
        (tipo, status, tentativas, max_tentativas,
         id_agendamento, id_usuario, email, nome,
         sala, inicio, fim, motivo, uid, sequence, created_at)
       VALUES
        ('RESET_SENHA', 'PENDENTE', 0, 5,
         NULL, NULL, ?, ?,
         NULL, NULL, NULL, ?, ?, 0, UTC_TIMESTAMP())`,
      [
        email,
        u[0].NOME || email,
        `Seu código de redefinição de senha é: ${code} (expira em ${expiresMinutes} min)`,
        uid
      ]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('password-reset/request:', err);
    return res.status(500).json({ success: false, message: 'Erro ao solicitar redefinição.', error: err.message });
  }
});



// =====================
// MARKETING (Volume /anexos)
// =====================
// Volume montado em /anexos (conforme seu Railway)
const PASTA_MARKETING = path.join(DIRETORIO_VOLUME_anexos, "marketing");

fs.mkdirSync(PASTA_MARKETING, { recursive: true });

// Servir imagens via URL (Express static) [web:650]
app.use("/anexos/marketing", express.static(PASTA_MARKETING));

function apenasNomeArquivoSeguro(nome) {
  const base = path.basename(String(nome || ""));
  return base.replace(/[^\w.\-() ]+/g, "_");
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PASTA_MARKETING),
  filename: (req, file, cb) => {
    const original = apenasNomeArquivoSeguro(file.originalname || "imagem");
    const ext = path.extname(original);
    const nomeSemExt = path.basename(original, ext);
    const unico = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    cb(null, `${nomeSemExt}-${unico}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ehImagem(file.mimetype)) return cb(new Error("Apenas imagens são permitidas."));
    cb(null, true);
  },
});

// LISTAR
app.get("/api/marketing/imagens", async (req, res) => {
  try {
    const files = await fs.promises.readdir(PASTA_MARKETING, { withFileTypes: true });

    const items = files
      .filter((d) => d.isFile())
      .map((d) => d.name)
      .filter((n) => /\.(png|jpe?g|gif|webp|bmp|svg)$/i.test(n))
      .sort((a, b) => a.localeCompare(b, "pt-BR"))
      .map((name) => ({
        name,
        url: `/anexos/marketing/${encodeURIComponent(name)}`,
      }));

    return res.json({ success: true, items });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Erro ao listar imagens.", error: err.message });
  }
});

// UPLOAD (múltiplos) - campo FormData: "files" [web:647]
app.post("/api/marketing/imagens", upload.array("files", 20), async (req, res) => {
  try {
    const arquivos = Array.isArray(req.files) ? req.files : [];

    if (!arquivos.length) {
      return res.status(400).json({
        success: false,
        message: "Nenhum arquivo recebido no campo 'files'."
      });
    }

    const items = arquivos.map((f) => ({
      name: f.filename,
      url: `/anexos/marketing/${encodeURIComponent(f.filename)}`,
      size: f.size,
      mimetype: f.mimetype,
    }));

    return res.status(201).json({ success: true, items });
  } catch (err) {
    console.error("ERRO UPLOAD MARKETING:", err);
    return res.status(400).json({
      success: false,
      message: err.message || "Erro ao enviar imagens."
    });
  }
});

// REMOVER
app.delete("/api/marketing/imagens/:nome", async (req, res) => {
  try {
    const nome = apenasNomeArquivoSeguro(req.params.nome);
    if (!nome) return res.status(400).json({ success: false, message: "Nome inválido." });

    const base = path.resolve(PASTA_MARKETING);
    const alvo = path.resolve(path.join(PASTA_MARKETING, nome));
    if (!alvo.startsWith(base + path.sep)) {
      return res.status(400).json({ success: false, message: "Caminho inválido." });
    }

    await fs.promises.unlink(alvo);
    return res.json({ success: true, message: "Imagem removida." });
  } catch (err) {
    if (err.code === "ENOENT") {
      return res.status(404).json({ success: false, message: "Arquivo não encontrado." });
    }
    return res.status(500).json({ success: false, message: "Erro ao remover imagem.", error: err.message });
  }
});

function normalizarUF(uf) {
  const s = (uf || '').toString().trim().toUpperCase();
  return s.length === 2 ? s : '';
}

function normalizarDocumento(doc) {
  return (doc || '').toString().replace(/\D+/g, '').trim(); // só números
}

function str(v) {
  const s = (v ?? '').toString().trim();
  return s ? s : '';
}

// GET /api/clientes?q=texto
app.get('/api/clientes', async (req, res) => {
  try {
    const q = (req.query.q || '').toString().trim();

    let sql = `
      SELECT
        ID, RAZAO_SOCIAL, DOCUMENTO, GRUPO_ECONOMICO,
        CIDADE, UF,
        CONTATO_NOME, CONTATO_TELEFONE, CONTATO_EMAIL,
        CULTURA_PRINCIPAL, HECTARES_ESTIMADOS, OBSERVACOES,
        ACTIVE, CREATED_AT, UPDATED_AT
      FROM SF_CLIENTE
      WHERE ACTIVE = 1
    `;
    const params = [];

    if (q) {
      sql += ` AND (RAZAO_SOCIAL LIKE ? OR DOCUMENTO LIKE ?) `;
      params.push(`%${q}%`, `%${normalizarDocumento(q)}%`);
    }

    sql += ` ORDER BY RAZAO_SOCIAL ASC `;

    const [rows] = await pool.query(sql, params);
    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao listar clientes.', error: err.message });
  }
});

// GET /api/clientes/:id
app.get('/api/clientes/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [rows] = await pool.query(
      `SELECT * FROM SF_CLIENTE WHERE ID = ? LIMIT 1`,
      [id]
    );
    if (!rows.length) return res.status(404).json({ success: false, message: 'Cliente não encontrado.' });
    return res.json({ success: true, item: rows[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao buscar cliente.', error: err.message });
  }
});


app.post('/api/clientes/salvar', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const c = req.body?.cliente || {};
    const filiais = Array.isArray(req.body?.filiais) ? req.body.filiais : [];

    const idCliente = Number(c.id || 0) || null;

    const razao = str(c.razao_social);
    const documento = normalizarDocumento(c.documento); // remove máscara (cpf/cnpj)
    const grupo = str(c.grupo_economico) || null;

    const cidade = str(c.cidade);
    const uf = normalizarUF(c.uf);

    const contatoNome = str(c.contato_nome) || null;
    const contatoTelefone = str(c.contato_telefone) || null;
    const contatoEmail = str(c.contato_email) || null;

    const cultura = str(c.cultura_principal) || null;
    const hectaresNum = Number(c.hectares_estimados);
    const hectares = Number.isFinite(hectaresNum) ? hectaresNum : null;
    const obs = str(c.observacoes) || null;

    if (!razao) return res.status(400).json({ success: false, message: 'razao_social é obrigatório.' });
    if (!documento) return res.status(400).json({ success: false, message: 'documento é obrigatório.' });
    if (!cidade) return res.status(400).json({ success: false, message: 'cidade é obrigatória.' });
    if (!uf) return res.status(400).json({ success: false, message: 'uf inválida (2 letras).' });

    await conn.beginTransaction();

    let idFinal = idCliente;

    if (idFinal) {
      const [r] = await conn.query(
        `UPDATE SF_CLIENTE
            SET RAZAO_SOCIAL = ?, DOCUMENTO = ?, GRUPO_ECONOMICO = ?,
                CIDADE = ?, UF = ?,
                CONTATO_NOME = ?, CONTATO_TELEFONE = ?, CONTATO_EMAIL = ?,
                CULTURA_PRINCIPAL = ?, HECTARES_ESTIMADOS = ?, OBSERVACOES = ?
          WHERE ID = ?`,
        [
          razao, documento, grupo,
          cidade, uf,
          contatoNome, contatoTelefone, contatoEmail,
          cultura, hectares, obs,
          idFinal
        ]
      );

      if (r.affectedRows === 0) {
        await conn.rollback();
        return res.status(404).json({ success: false, message: 'Cliente não encontrado.' });
      }
    } else {
      const [r] = await conn.query(
        `INSERT INTO SF_CLIENTE
         (RAZAO_SOCIAL, DOCUMENTO, GRUPO_ECONOMICO, CIDADE, UF,
          CONTATO_NOME, CONTATO_TELEFONE, CONTATO_EMAIL,
          CULTURA_PRINCIPAL, HECTARES_ESTIMADOS, OBSERVACOES, ACTIVE)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
        [
          razao, documento, grupo, cidade, uf,
          contatoNome, contatoTelefone, contatoEmail,
          cultura, hectares, obs
        ]
      );
      idFinal = r.insertId;
    }

    // ---------- sincronizar filiais ----------
    const [exist] = await conn.query(
      `SELECT ID FROM SF_CLIENTE_FILIAL WHERE ID_CLIENTE = ? AND ACTIVE = 1`,
      [idFinal]
    );

    const idsExistentes = exist.map(x => Number(x.ID)).filter(n => Number.isFinite(n) && n > 0);
    const idsFormulario = filiais.map(f => Number(f.id || 0)).filter(n => Number.isFinite(n) && n > 0);

    const idsParaDesativar = idsExistentes.filter(id => !idsFormulario.includes(id));
    if (idsParaDesativar.length) {
      await conn.query(
        `UPDATE SF_CLIENTE_FILIAL SET ACTIVE = 0 WHERE ID_CLIENTE = ? AND ID IN (?)`,
        [idFinal, idsParaDesativar]
      );
    }

    for (const f of filiais) {
      const fid = Number(f.id || 0) || null;

      const nome = str(f.nome);
      const endereco = str(f.endereco) || null;
      const fCidade = str(f.cidade);
      const fUf = normalizarUF(f.uf);
      const fContatoNome = str(f.contato_nome) || null;
      const fContatoTelefone = str(f.contato_telefone) || null;

      if (!nome) { await conn.rollback(); return res.status(400).json({ success: false, message: 'Filial: nome é obrigatório.' }); }
      if (!fCidade) { await conn.rollback(); return res.status(400).json({ success: false, message: 'Filial: cidade é obrigatória.' }); }
      if (!fUf) { await conn.rollback(); return res.status(400).json({ success: false, message: 'Filial: uf inválida (2 letras).' }); }

      if (fid) {
        await conn.query(
          `UPDATE SF_CLIENTE_FILIAL
              SET NOME = ?, ENDERECO = ?, CIDADE = ?, UF = ?,
                  CONTATO_NOME = ?, CONTATO_TELEFONE = ?, ACTIVE = 1
            WHERE ID = ? AND ID_CLIENTE = ?`,
          [nome, endereco, fCidade, fUf, fContatoNome, fContatoTelefone, fid, idFinal]
        );
      } else {
        await conn.query(
          `INSERT INTO SF_CLIENTE_FILIAL
           (ID_CLIENTE, NOME, ENDERECO, CIDADE, UF, CONTATO_NOME, CONTATO_TELEFONE, ACTIVE)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
          [idFinal, nome, endereco, fCidade, fUf, fContatoNome, fContatoTelefone]
        );
      }
    }

    await conn.commit();
    return res.status(200).json({ success: true, id: idFinal });
  } catch (err) {
    try { await conn.rollback(); } catch {}

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Já existe cliente com este documento.' });
    }

    return res.status(500).json({ success: false, message: 'Erro ao salvar cliente.', error: err.message });
  } finally {
    conn.release();
  }
});

// PUT /api/clientes/:id
app.put('/api/clientes/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const razao = str(req.body?.razao_social);
    const documento = normalizarDocumento(req.body?.documento);
    const grupo = str(req.body?.grupo_economico) || null;

    const cidade = str(req.body?.cidade);
    const uf = normalizarUF(req.body?.uf);

    const contatoNome = str(req.body?.contato_nome) || null;
    const contatoTelefone = str(req.body?.contato_telefone) || null;
    const contatoEmail = str(req.body?.contato_email) || null;

    const cultura = str(req.body?.cultura_principal) || null;
    const hectares = Number(req.body?.hectares_estimados);
    const obs = str(req.body?.observacoes) || null;

    if (!razao) return res.status(400).json({ success: false, message: 'razao_social é obrigatório.' });
    if (!documento) return res.status(400).json({ success: false, message: 'documento é obrigatório.' });
    if (!cidade) return res.status(400).json({ success: false, message: 'cidade é obrigatória.' });
    if (!uf) return res.status(400).json({ success: false, message: 'uf inválida (2 letras).' });

    const [r] = await pool.query(
      `UPDATE SF_CLIENTE
          SET RAZAO_SOCIAL = ?, DOCUMENTO = ?, GRUPO_ECONOMICO = ?,
              CIDADE = ?, UF = ?,
              CONTATO_NOME = ?, CONTATO_TELEFONE = ?, CONTATO_EMAIL = ?,
              CULTURA_PRINCIPAL = ?, HECTARES_ESTIMADOS = ?, OBSERVACOES = ?
        WHERE ID = ?`,
      [
        razao, documento, grupo,
        cidade, uf,
        contatoNome, contatoTelefone, contatoEmail,
        cultura, Number.isFinite(hectares) ? hectares : null, obs,
        id
      ]
    );

    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Cliente não encontrado.' });
    return res.json({ success: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Já existe cliente com este documento.' });
    }
    return res.status(500).json({ success: false, message: 'Erro ao atualizar cliente.', error: err.message });
  }
});

// DELETE /api/clientes/:id
app.delete('/api/clientes/:id(\\d+)', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const id = Number(req.params.id);

    await conn.beginTransaction();

    // desativa filiais ativas
    await conn.query(
      `UPDATE SF_CLIENTE_FILIAL SET ACTIVE = 0 WHERE ID_CLIENTE = ? AND ACTIVE = 1`,
      [id]
    );

    // desativa cliente
    const [r] = await conn.query(
      `UPDATE SF_CLIENTE SET ACTIVE = 0 WHERE ID = ? AND ACTIVE = 1`,
      [id]
    );

    if (r.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Cliente não encontrado ou já desativado.' });
    }

    await conn.commit();
    return res.json({ success: true });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    return res.status(500).json({ success: false, message: 'Erro ao desativar cliente.', error: err.message });
  } finally {
    conn.release();
  }
});

// GET /api/clientes/:id/filiais
app.get('/api/clientes/:id(\\d+)/filiais', async (req, res) => {
  try {
    const idCliente = Number(req.params.id);

    const [rows] = await pool.query(
      `SELECT ID, ID_CLIENTE, NOME, ENDERECO, CIDADE, UF, CONTATO_NOME, CONTATO_TELEFONE, ACTIVE, CREATED_AT, UPDATED_AT
         FROM SF_CLIENTE_FILIAL
        WHERE ID_CLIENTE = ? AND ACTIVE = 1
        ORDER BY NOME ASC`,
      [idCliente]
    );

    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao listar filiais.', error: err.message });
  }
});

// POST /api/clientes/:id/filiais
app.post('/api/clientes/:id(\\d+)/filiais', async (req, res) => {
  try {
    const idCliente = Number(req.params.id);

    const nome = str(req.body?.nome);
    const endereco = str(req.body?.endereco) || null;
    const cidade = str(req.body?.cidade);
    const uf = normalizarUF(req.body?.uf);
    const contatoNome = str(req.body?.contato_nome) || null;
    const contatoTelefone = str(req.body?.contato_telefone) || null;

    if (!nome) return res.status(400).json({ success: false, message: 'nome é obrigatório.' });
    if (!cidade) return res.status(400).json({ success: false, message: 'cidade é obrigatória.' });
    if (!uf) return res.status(400).json({ success: false, message: 'uf inválida (2 letras).' });

    const [r] = await pool.query(
      `INSERT INTO SF_CLIENTE_FILIAL
       (ID_CLIENTE, NOME, ENDERECO, CIDADE, UF, CONTATO_NOME, CONTATO_TELEFONE, ACTIVE)
       VALUES (?, ?, ?, ?, ?, ?, ?, 1)`,
      [idCliente, nome, endereco, cidade, uf, contatoNome, contatoTelefone]
    );

    return res.status(201).json({ success: true, item: { id: r.insertId } });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao criar filial.', error: err.message });
  }
});

// PUT /api/filiais/:id
app.put('/api/filiais/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const nome = str(req.body?.nome);
    const endereco = str(req.body?.endereco) || null;
    const cidade = str(req.body?.cidade);
    const uf = normalizarUF(req.body?.uf);
    const contatoNome = str(req.body?.contato_nome) || null;
    const contatoTelefone = str(req.body?.contato_telefone) || null;

    if (!nome) return res.status(400).json({ success: false, message: 'nome é obrigatório.' });
    if (!cidade) return res.status(400).json({ success: false, message: 'cidade é obrigatória.' });
    if (!uf) return res.status(400).json({ success: false, message: 'uf inválida (2 letras).' });

    const [r] = await pool.query(
      `UPDATE SF_CLIENTE_FILIAL
          SET NOME = ?, ENDERECO = ?, CIDADE = ?, UF = ?, CONTATO_NOME = ?, CONTATO_TELEFONE = ?
        WHERE ID = ?`,
      [nome, endereco, cidade, uf, contatoNome, contatoTelefone, id]
    );

    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Filial não encontrada.' });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao atualizar filial.', error: err.message });
  }
});

// DELETE /api/filiais/:id
app.delete('/api/filiais/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [r] = await pool.query(`UPDATE SF_CLIENTE_FILIAL SET ACTIVE = 0 WHERE ID = ? AND ACTIVE = 1`, [id]);
    if (r.affectedRows === 0) return res.status(404).json({ success: false, message: 'Filial não encontrada ou já desativada.' });
    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Erro ao desativar filial.', error: err.message });
  }
});

// Leitura de email automatico as 06:00 e as 20:00 //

const MS_TENANT_ID = process.env.MS_TENANT_ID;
const MS_CLIENT_ID = process.env.MS_CLIENT_ID;
const MS_CLIENT_SECRET = process.env.MS_CLIENT_SECRET;
const MS_USER_EMAIL = process.env.MS_USER_EMAIL;

async function obterAccessTokenGraph() {
  const url = `https://login.microsoftonline.com/${MS_TENANT_ID}/oauth2/v2.0/token`;
  const params = new URLSearchParams();
  params.append('client_id', MS_CLIENT_ID);
  params.append('client_secret', MS_CLIENT_SECRET);
  params.append('scope', 'https://graph.microsoft.com/.default');
  params.append('grant_type', 'client_credentials');

  const resp = await fetch(url, {
    method: 'POST',
    body: params,
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error('Falha ao obter token Graph: ' + txt);
  }

  const data = await resp.json();
  return data.access_token;
}

async function graphRequest(path, options = {}) {
  const token = await obterAccessTokenGraph();
  const url = `https://graph.microsoft.com/v1.0${path}`;

  const resp = await fetch(url, {
    ...options,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Graph erro ${resp.status}: ${txt}`);
  }

  return resp.json();
}

async function processarEmailsOffice365() {
  const conn = await pool.getConnection();

  try {
    // 1) Carrega remetentes
    const [remRows] = await conn.query(
      `SELECT ID, EMAIL
         FROM SF_EMAIL_REMETENTE
        WHERE ATIVO = 1`
    );

    if (!remRows.length) {
      conn.release();
      return;
    }

    const remetentes = remRows.map(r => ({
      id: r.ID,
      email: (r.EMAIL || '').toLowerCase().trim(),
    }));

    // 2) Carrega destinatários por remetente
    const [destRows] = await conn.query(
      `SELECT ID_REMETENTE, EMAIL_DESTINATARIO
         FROM SF_EMAIL_DESTINATARIOS
        WHERE ATIVO = 1`
    );

    const mapaDestinatarios = new Map();
    for (const d of destRows) {
      const idRem = d.ID_REMETENTE;
      const emailDest = (d.EMAIL_DESTINATARIO || '').toLowerCase().trim();
      if (!mapaDestinatarios.has(idRem)) {
        mapaDestinatarios.set(idRem, new Set());
      }
      mapaDestinatarios.get(idRem).add(emailDest);
    }

    if (!destRows.length) {
      conn.release();
      return;
    }

    // 3) Busca emails recentes na caixa de entrada
    // Exemplo: últimas 48h, apenas não deletados
    const filtroData = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    const path =
      `/users/${encodeURIComponent(MS_USER_EMAIL)}/mailFolders/Inbox/messages` +
      `?$top=50&$filter=receivedDateTime ge ${filtroData}`;

    const data = await graphRequest(path);
    const mensagens = Array.isArray(data.value) ? data.value : [];


    for (const msg of mensagens) {
      const messageId = msg.id;
      const assunto = msg.subject || '';
      const recebidoEm = msg.receivedDateTime || null;

      const fromEmail =
        msg.from?.emailAddress?.address?.toLowerCase().trim() || '';
      const toRecipients = Array.isArray(msg.toRecipients)
        ? msg.toRecipients
        : [];

      // tenta casar remetente
      const remetente = remetentes.find(r => r.email === fromEmail);
      if (!remetente) continue;

      const listaDestinatarios = mapaDestinatarios.get(remetente.id);
      if (!listaDestinatarios || !listaDestinatarios.size) continue;

      for (const dest of toRecipients) {
        const destEmail =
          dest.emailAddress?.address?.toLowerCase().trim() || '';
        if (!listaDestinatarios.has(destEmail)) continue;

        // verifica se já foi processado (pela tabela, não pelo Outlook)
        const [ja] = await conn.query(
          `SELECT ID, LIDO_TABELA
             FROM SF_EMAIL_PROCESSADO
            WHERE MESSAGE_ID = ? AND DESTINATARIO_EMAIL = ?
            LIMIT 1`,
          [messageId, destEmail]
        );

        if (ja.length && ja[0].LIDO_TABELA === 1) {
          continue; // já processado
        }

        let idProcessado;
        if (!ja.length) {
          const [ins] = await conn.query(
            `INSERT INTO SF_EMAIL_PROCESSADO
              (MESSAGE_ID, REMETENTE_EMAIL, DESTINATARIO_EMAIL,
               ASSUNTO, RECEBIDO_EM, LIDO_TABELA, LIDO_OUTLOOK)
             VALUES (?, ?, ?, ?, ?, 0, 0)`,
            [
              messageId,
              fromEmail,
              destEmail,
              assunto,
              recebidoEm ? new Date(recebidoEm) : null,
            ]
          );
          idProcessado = ins.insertId;
        } else {
          idProcessado = ja[0].ID;
        }

        // 4) Baixar anexos e salvar
        await baixarESalvarAnexos(conn, idProcessado, messageId);

        // 5) Marca como lido na tabela
        await conn.query(
          `UPDATE SF_EMAIL_PROCESSADO
              SET LIDO_TABELA = 1
            WHERE ID = ?`,
          [idProcessado]
        );

        // 6) Opcional: marcar como lido no Outlook
        try {
          await marcarEmailComoLidoOutlook(messageId);
          await conn.query(
            `UPDATE SF_EMAIL_PROCESSADO
                SET LIDO_OUTLOOK = 1
              WHERE ID = ?`,
            [idProcessado]
          );
        } catch (e) {
          console.error(
            'Falha ao marcar como lido no Outlook (continua assim mesmo):',
            e.message
          );
        }
      }
    }

    conn.release();
  } catch (err) {
    conn.release();
    console.error('Erro em processarEmailsOffice365:', err);
  }
}

async function baixarESalvarAnexos(conn, emailProcessadoId, messageId) {
  // pega a lista de attachments
  const path = `/users/${encodeURIComponent(
    MS_USER_EMAIL
  )}/messages/${messageId}/attachments`;

  const data = await graphRequest(path);
  const anexos = Array.isArray(data.value) ? data.value : [];

  for (const at of anexos) {
    // fileAttachment tem contentBytes
    if (
      at['@odata.type'] !== '#microsoft.graph.fileAttachment' ||
      !at.contentBytes
    ) {
      continue;
    }

    const nomeOriginal = at.name || 'anexo';
    const contentType = at.contentType || null;
    const buffer = Buffer.from(at.contentBytes, 'base64');

    const { caminhoAbsoluto, caminhoRelativo, nomeFinal } =
      gerarCaminhoAnexo(nomeOriginal);

    // grava arquivo no volume
    await fs.promises.writeFile(caminhoAbsoluto, buffer);

    await conn.query(
      `INSERT INTO SF_EMAIL_ANEXO
        (EMAIL_PROCESSADO_ID, NOME_ORIGINAL, NOME_SALVO,
         CAMINHO_RELATIVO, TAMANHO_BYTES, CONTENT_TYPE)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        emailProcessadoId,
        nomeOriginal,
        nomeFinal,
        caminhoRelativo,
        buffer.length,
        contentType,
      ]
    );
  }
}

async function marcarEmailComoLidoOutlook(messageId) {
  const path = `/users/${encodeURIComponent(
    MS_USER_EMAIL
  )}/messages/${messageId}`;
  const token = await obterAccessTokenGraph();
  const url = `https://graph.microsoft.com/v1.0${path}`;

  const resp = await fetch(url, {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ isRead: true }),
  });

  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error(`Erro ao marcar email como lido: ${txt}`);
  }
}

// todos os dias às 06:00
cron.schedule('0 6 * * *', () => {
  processarEmailsOffice365();
});

// todos os dias às 20:00
cron.schedule('0 20 * * *', () => {
  processarEmailsOffice365();
});

app.post('/cron/processar-emails-office365', async (req, res) => {
  processarEmailsOffice365()
    .then(() => res.json({ ok: true }))
    .catch(err => {
      console.error(err);
      res.status(500).json({ ok: false, erro: err.message });
    });
});

app.post('/test-emails-office365', async (req, res) => {
  await processarEmailsOffice365();
  res.json({ ok: true, message: 'Job executado!' });
});

function textoLivre(v) {
  return String(v ?? '').trim();
}

function normalizarDocumentoPDF(v) {
  return String(v ?? '').replace(/\D+/g, '').trim();
}

function parseDecimalBr(v) {
  const s = String(v ?? '').trim();
  if (!s) return 0;
  return Number(s.replace(/\./g, '').replace(',', '.')) || 0;
}

function dataBrParaMysql(v) {
  const s = String(v ?? '').trim();
  if (!s) return null;

  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) return null;

  const [, dd, mm, yyyy] = m;
  return `${yyyy}-${mm}-${dd}`;
}

// importação Nota PDF

app.get('/api/estoque/produtos', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT
         id AS ID,
         codigo AS CODIGO,
         descricao AS DESCRICAO,
         unidade AS UNIDADE
       FROM SF_PRODUTOS
       WHERE ativo = 1
       ORDER BY descricao ASC`
    );

    return res.json({ success: true, items: rows });
  } catch (err) {
    console.error('Erro /api/estoque/produtos GET:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar produtos.',
      error: err.message
    });
  }
});

app.post('/api/estoque/produtos', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const descricao = textoLivre(req.body?.descricao).toUpperCase();
    const unidade = textoLivre(req.body?.unidade).toUpperCase() || null;
    let codigo = textoLivre(req.body?.codigo).toUpperCase();

    if (!descricao) {
      return res.status(400).json({ success: false, message: 'Descrição é obrigatória.' });
    }

    await conn.beginTransaction();

    if (!codigo) {
      codigo = await gerarProximoCodigoProduto(conn);
    }

    const [r] = await conn.query(
      `INSERT INTO SF_PRODUTOS (codigo, descricao, unidade, ativo)
       VALUES (?, ?, ?, 1)`,
      [codigo, descricao, unidade]
    );

    await conn.commit();

    return res.status(201).json({
      success: true,
      item: {
        ID: r.insertId,
        CODIGO: codigo,
        DESCRICAO: descricao,
        UNIDADE: unidade
      }
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/estoque/produtos POST:', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Já existe produto com esse código.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar produto.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.post('/api/estoque/importacao-pdf/validar', async (req, res) => {
  try {
    const cnpjEmitente = normalizarDocumentoPDF(req.body?.emitenteCnpj);
    const itens = Array.isArray(req.body?.itens) ? req.body.itens : [];

    if (!cnpjEmitente) {
      return res.status(400).json({
        success: false,
        message: 'CNPJ do emitente é obrigatório.'
      });
    }

    const [fornecedorRows] = await pool.query(
      `SELECT id, razao_social, cnpj
       FROM SF_FORNECEDOR
       WHERE cnpj = ?
       LIMIT 1`,
      [cnpjEmitente]
    );

    const fornecedor = fornecedorRows[0] || null;

    if (!fornecedor || !itens.length) {
      return res.json({
        success: true,
        fornecedorEncontrado: !!fornecedor,
        fornecedor,
        itens: itens.map(item => ({
          codigo: item.codigo || '',
          descricao: item.descricao || '',
          vinculado: false,
          multiplosVinculos: false,
          produtosVinculados: [],
          produto: null
        }))
      });
    }

    const codigos = [...new Set(
      itens.map(item => textoLivre(item.codigo)).filter(Boolean)
    )];

    if (!codigos.length) {
      return res.json({
        success: true,
        fornecedorEncontrado: true,
        fornecedor,
        itens: itens.map(item => ({
          codigo: item.codigo || '',
          descricao: item.descricao || '',
          vinculado: false,
          multiplosVinculos: false,
          produtosVinculados: [],
          produto: null
        }))
      });
    }

    const placeholders = codigos.map(() => '?').join(',');

    const [amarracoes] = await pool.query(
      `
      SELECT
        A.id AS ID,
        A.produto_fornecedor_codigo AS COD_PRODUTO_NF,
        A.produto_fornecedor_descricao AS DESCRICAO_PRODUTO_NF,
        A.produto_sistema_id AS ID_PRODUTO,
        P.codigo AS CODIGO_SISTEMA,
        P.descricao AS DESCRICAO_SISTEMA,
        P.unidade AS UNIDADE_SISTEMA
      FROM SF_PRODUTOS_AMARRACAO A
      INNER JOIN SF_PRODUTOS P
              ON P.id = A.produto_sistema_id
      WHERE A.fornecedor_id = ?
        AND A.produto_fornecedor_codigo IN (${placeholders})
      ORDER BY P.descricao ASC
      `,
      [fornecedor.id, ...codigos]
    );

    const mapa = new Map();

    for (const am of amarracoes) {
      const chave = textoLivre(am.COD_PRODUTO_NF);
      if (!mapa.has(chave)) mapa.set(chave, []);
      mapa.get(chave).push({
        ID_AMARRACAO: am.ID,
        ID: am.ID_PRODUTO,
        CODIGO: am.CODIGO_SISTEMA,
        DESCRICAO: am.DESCRICAO_SISTEMA,
        UNIDADE: am.UNIDADE_SISTEMA
      });
    }

    return res.json({
      success: true,
      fornecedorEncontrado: true,
      fornecedor,
      itens: itens.map(item => {
        const codigo = textoLivre(item.codigo);
        const vinculados = mapa.get(codigo) || [];

        return {
          codigo: item.codigo || '',
          descricao: item.descricao || '',
          vinculado: vinculados.length > 0,
          multiplosVinculos: vinculados.length > 1,
          produtosVinculados: vinculados,
          produto: vinculados.length === 1 ? vinculados[0] : null
        };
      })
    });
  } catch (err) {
    console.error('Erro /api/estoque/importacao-pdf/validar:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao validar importação do PDF.',
      error: err.message
    });
  }
});

async function gerarProximoCodigoProduto(connOuPool = pool) {
  const [rows] = await connOuPool.query(`
    SELECT MAX(CAST(codigo AS UNSIGNED)) AS ULTIMO
    FROM SF_PRODUTOS
    WHERE codigo REGEXP '^[0-9]+$'
  `);

  const ultimo = Number(rows?.[0]?.ULTIMO || 0);
  const proximo = ultimo + 1;

  return String(proximo).padStart(6, '0');
}

app.get('/api/estoque/produtos/proximo-codigo', async (req, res) => {
  try {
    const codigo = await gerarProximoCodigoProduto(pool);

    return res.json({
      success: true,
      codigo
    });
  } catch (err) {
    console.error('Erro /api/estoque/produtos/proximo-codigo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao gerar próximo código do produto.',
      error: err.message
    });
  }
});

app.post('/api/estoque/produtos-amarracao/adicionar', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const idFornecedor = Number(req.body?.id_fornecedor);
    const codProdutoNf = textoLivre(req.body?.cod_produto_nf);
    const descricaoProdutoNf = textoLivre(req.body?.descricao_produto_nf).toUpperCase() || null;
    const idProduto = Number(req.body?.id_produto);
    const usuario = textoLivre(req.body?.usuario);

    if (!idFornecedor) {
      return res.status(400).json({ success: false, message: 'Fornecedor é obrigatório.' });
    }

    if (!codProdutoNf) {
      return res.status(400).json({ success: false, message: 'Código do produto da nota é obrigatório.' });
    }

    if (!idProduto) {
      return res.status(400).json({ success: false, message: 'Produto do sistema é obrigatório.' });
    }

    await conn.beginTransaction();

    const [jaExiste] = await conn.query(
      `
      SELECT id
      FROM SF_PRODUTOS_AMARRACAO
      WHERE fornecedor_id = ?
        AND produto_fornecedor_codigo = ?
        AND produto_sistema_id = ?
      LIMIT 1
      `,
      [idFornecedor, codProdutoNf, idProduto]
    );

    if (jaExiste.length) {
      await conn.rollback();
      return res.json({
        success: true,
        id: jaExiste[0].id,
        jaExistia: true,
        message: 'Vínculo já existente.'
      });
    }

    const [r] = await conn.query(
      `
      INSERT INTO SF_PRODUTOS_AMARRACAO
      (
        fornecedor_id,
        produto_fornecedor_codigo,
        produto_fornecedor_descricao,
        produto_sistema_id
      )
      VALUES (?, ?, ?, ?)
      `,
      [idFornecedor, codProdutoNf, descricaoProdutoNf, idProduto]
    );

    await conn.query(
      `
      INSERT INTO SF_PRODUTOS_AMARRACAO_LOG
      (
        amarracao_id,
        fornecedor_id,
        produto_fornecedor_codigo,
        produto_fornecedor_descricao,
        produto_sistema_id_anterior,
        produto_sistema_id_novo,
        acao,
        usuario
      )
      VALUES (?, ?, ?, ?, ?, ?, 'CRIAR', ?)
      `,
      [r.insertId, idFornecedor, codProdutoNf, descricaoProdutoNf, null, idProduto, usuario || null]
    );

    await conn.commit();

    return res.json({
      success: true,
      id: r.insertId,
      jaExistia: false,
      message: 'Vínculo salvo com sucesso.'
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/estoque/produtos-amarracao/adicionar:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao adicionar vínculo.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.put('/api/estoque/produtos-amarracao/:id', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const idAmarracao = Number(req.params.id);
    const idProduto = Number(req.body?.id_produto);
    const usuario = textoLivre(req.body?.usuario);

    if (!idAmarracao) {
      return res.status(400).json({ success: false, message: 'ID da amarração é obrigatório.' });
    }

    if (!idProduto) {
      return res.status(400).json({ success: false, message: 'Produto do sistema é obrigatório.' });
    }

    await conn.beginTransaction();

    const [rows] = await conn.query(
      `
      SELECT id, fornecedor_id, produto_fornecedor_codigo, produto_fornecedor_descricao, produto_sistema_id
      FROM SF_PRODUTOS_AMARRACAO
      WHERE id = ?
      LIMIT 1
      `,
      [idAmarracao]
    );

    const atual = rows[0];

    if (!atual) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Amarração não encontrada.' });
    }

    await conn.query(
      `
      UPDATE SF_PRODUTOS_AMARRACAO
      SET produto_sistema_id = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
      `,
      [idProduto, idAmarracao]
    );

    await conn.query(
      `
      INSERT INTO SF_PRODUTOS_AMARRACAO_LOG
      (
        amarracao_id,
        fornecedor_id,
        produto_fornecedor_codigo,
        produto_fornecedor_descricao,
        produto_sistema_id_anterior,
        produto_sistema_id_novo,
        acao,
        usuario
      )
      VALUES (?, ?, ?, ?, ?, ?, 'EDITAR', ?)
      `,
      [
        atual.id,
        atual.fornecedor_id,
        atual.produto_fornecedor_codigo,
        atual.produto_fornecedor_descricao,
        atual.produto_sistema_id,
        idProduto,
        usuario || null
      ]
    );

    await conn.commit();

    return res.json({ success: true });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro PUT /api/estoque/produtos-amarracao/:id:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao editar vínculo.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.post('/api/estoque/importacao-pdf/confirmar', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const emitente = textoLivre(req.body?.emitente).toUpperCase();
    const emitenteCnpj = normalizarDocumentoPDF(req.body?.emitenteCnpj);
    const destinatarioCnpj = normalizarDocumentoPDF(req.body?.destinatarioCnpj);
    const numeroNota = textoLivre(req.body?.numeroNota);
    const serie = textoLivre(req.body?.serie) || null;
    const dataEmissao = dataBrParaMysql(req.body?.dataEmissao);
    const usuarioRegistro = textoLivre(req.body?.usuarioRegistro);
    const local = textoLivre(req.body?.local).toUpperCase() || null;
    const idLocalAlmoxarifado = Number(req.body?.idLocalAlmoxarifado) || null;
    const itens = Array.isArray(req.body?.itens) ? req.body.itens : [];

    if (!emitenteCnpj) {
      return res.status(400).json({
        success: false,
        message: 'CNPJ do emitente é obrigatório.'
      });
    }

    if (!numeroNota) {
      return res.status(400).json({
        success: false,
        message: 'Número da nota é obrigatório.'
      });
    }

    if (!dataEmissao) {
      return res.status(400).json({
        success: false,
        message: 'Data de emissão inválida.'
      });
    }

    if (!idLocalAlmoxarifado) {
      return res.status(400).json({
        success: false,
        message: 'Local de armazenagem é obrigatório.'
      });
    }

    if (!itens.length) {
      return res.status(400).json({
        success: false,
        message: 'Nenhum item informado para importação.'
      });
    }

    await conn.beginTransaction();

    const [localRows] = await conn.query(
      `
      SELECT ID, NOME
      FROM SF_LOCAL_ALMOXARIFADO
      WHERE ID = ?
      LIMIT 1
      `,
      [idLocalAlmoxarifado]
    );

    const localSelecionado = localRows[0] || null;

    if (!localSelecionado) {
      throw new Error('Local de armazenagem não encontrado.');
    }

    const nomeLocal = textoLivre(localSelecionado.NOME).toUpperCase() || local;

    let [fornecedorRows] = await conn.query(
      `
      SELECT id, razao_social, cnpj
      FROM SF_FORNECEDOR
      WHERE cnpj = ?
      LIMIT 1
      `,
      [emitenteCnpj]
    );

    let fornecedor = fornecedorRows[0] || null;

    if (!fornecedor) {
      const [rFornecedor] = await conn.query(
        `
        INSERT INTO SF_FORNECEDOR (razao_social, cnpj)
        VALUES (?, ?)
        `,
        [emitente || emitenteCnpj, emitenteCnpj]
      );

      [fornecedorRows] = await conn.query(
        `
        SELECT id, razao_social, cnpj
        FROM SF_FORNECEDOR
        WHERE id = ?
        LIMIT 1
        `,
        [rFornecedor.insertId]
      );

      fornecedor = fornecedorRows[0] || null;
    }

    const [entradaExistente] = await conn.query(
      `
      SELECT id
      FROM SF_PRODUTO_ENTRADA
      WHERE cnpj_emitente = ?
        AND nota = ?
        AND (
          (serie IS NULL AND ? IS NULL)
          OR serie = ?
        )
      LIMIT 1
      `,
      [emitenteCnpj, numeroNota, serie, serie]
    );

    if (entradaExistente.length) {
      throw new Error(
        `A nota ${numeroNota} série ${serie || 'SEM SÉRIE'} do emitente ${emitenteCnpj} já foi importada.`
      );
    }

    for (const item of itens) {
      const codProdutoNf = textoLivre(item.codigo);
      const descricaoProdutoNf = textoLivre(item.descricao).toUpperCase() || null;
      const unidade = textoLivre(item.unidade).toUpperCase() || null;
      const idProduto = Number(item.idproduto || item.id_produto);
      const codProdutoSistema = textoLivre(item.codprodutosistema || item.cod_produto_sistema).toUpperCase();
      const descricaoProdutoSistema = textoLivre(item.descricaoprodutosistema || item.descricao_produto_sistema).toUpperCase() || null;
      const qtd = parseDecimalBr(item.quantidade);
      const valorUnit = parseDecimalBr(item.valorUnitario);
      const valorTotal = parseDecimalBr(item.valorTotal);

      if (!codProdutoNf) {
        throw new Error('Existe item sem código do produto na nota.');
      }

      if (!idProduto) {
        throw new Error(`O item ${codProdutoNf} está sem produto do sistema vinculado.`);
      }

      if (!codProdutoSistema) {
        throw new Error(`O item ${codProdutoNf} está sem código do produto do sistema.`);
      }

      const [produtoRows] = await conn.query(
        `
        SELECT id, codigo, descricao, unidade
        FROM SF_PRODUTOS
        WHERE id = ?
          AND ativo = 1
        LIMIT 1
        `,
        [idProduto]
      );

      const produtoSistema = produtoRows[0] || null;

      if (!produtoSistema) {
        throw new Error(`Produto do sistema não encontrado para o item ${codProdutoNf}.`);
      }

      const [amarracaoExistente] = await conn.query(
        `
        SELECT id
        FROM SF_PRODUTOS_AMARRACAO
        WHERE fornecedor_id = ?
          AND produto_fornecedor_codigo = ?
          AND produto_sistema_id = ?
        LIMIT 1
        `,
        [fornecedor.id, codProdutoNf, idProduto]
      );

      if (!amarracaoExistente.length) {
        const [rAmarracao] = await conn.query(
          `
          INSERT INTO SF_PRODUTOS_AMARRACAO
          (
            fornecedor_id,
            produto_fornecedor_codigo,
            produto_fornecedor_descricao,
            produto_sistema_id
          )
          VALUES (?, ?, ?, ?)
          `,
          [fornecedor.id, codProdutoNf, descricaoProdutoNf, idProduto]
        );

        await conn.query(
          `
          INSERT INTO SF_PRODUTOS_AMARRACAO_LOG
          (
            amarracao_id,
            fornecedor_id,
            produto_fornecedor_codigo,
            produto_fornecedor_descricao,
            produto_sistema_id_anterior,
            produto_sistema_id_novo,
            acao,
            usuario
          )
          VALUES (?, ?, ?, ?, ?, ?, 'CRIAR_IMPORTACAO', ?)
          `,
          [
            rAmarracao.insertId,
            fornecedor.id,
            codProdutoNf,
            descricaoProdutoNf,
            null,
            idProduto,
            usuarioRegistro || null
          ]
        );
      }

      const payloadEntradaLog = {
        fornecedor_id: fornecedor.id,
        nota: numeroNota,
        serie,
        cnpj_emitente: emitenteCnpj,
        cnpj_remetente: destinatarioCnpj || null,
        data_emissao: dataEmissao,
        usuario_registro: usuarioRegistro || null,
        qtd_nf: qtd,
        valor_unitario_nf: valorUnit,
        valor_total_nf: valorTotal,
        cod_produto_nf: codProdutoNf,
        descricao_produto_nf: descricaoProdutoNf,
        unidade_nf: unidade,
        cod_produto_sistema: codProdutoSistema,
        descricao_produto_sistema: descricaoProdutoSistema,
        produto_sistema_id: idProduto,
        local: nomeLocal,
        id_local_almoxarifado: idLocalAlmoxarifado
      };

      const [rEntrada] = await conn.query(
        `
        INSERT INTO SF_PRODUTO_ENTRADA
        (
          fornecedor_id,
          nota,
          serie,
          cnpj_emitente,
          cnpj_remetente,
          data_emissao,
          data_registro,
          usuario_registro,
          qtd_nf,
          valor_unitario_nf,
          valor_total_nf,
          cod_produto_nf,
          descricao_produto_nf,
          unidade_nf,
          cod_produto_sistema,
          produto_sistema_id,
          LOCAL,
          ID_LOCAL_ALMOXARIFADO,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `,
        [
          fornecedor.id,
          numeroNota,
          serie,
          emitenteCnpj,
          destinatarioCnpj || null,
          dataEmissao,
          usuarioRegistro || null,
          qtd,
          valorUnit,
          valorTotal,
          codProdutoNf,
          descricaoProdutoNf,
          unidade,
          codProdutoSistema,
          idProduto,
          nomeLocal,
          idLocalAlmoxarifado
        ]
      );

      await registrarLogProdutoEntrada(conn, {
        idEntrada: rEntrada.insertId,
        acao: 'INSERT',
        usuario: usuarioRegistro || null,
        antes: null,
        depois: {
          id: rEntrada.insertId,
          ...payloadEntradaLog
        },
        observacao: 'Registro criado via importação de Nota Fiscal'
      });
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Importação realizada com sucesso.',
      fornecedor
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/estoque/importacao-pdf/confirmar:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao confirmar importação do PDF.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.get('/api/locais-almoxarifado', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT ID, NOME
      FROM SF_LOCAL_ALMOXARIFADO
      WHERE ATIVO = 1
      ORDER BY NOME ASC
    `);

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao listar locais.' });
  }
});

app.post('/api/locais-almoxarifado', async (req, res) => {
  try {
    const nome = String(req.body?.nome || '').trim().toUpperCase();

    if (!nome) {
      return res.status(400).json({ erro: 'Informe o nome do local.' });
    }

    const [existente] = await pool.query(
      `SELECT ID FROM SF_LOCAL_ALMOXARIFADO WHERE UPPER(NOME) = ? LIMIT 1`,
      [nome]
    );

    if (existente.length) {
      return res.status(409).json({ erro: 'Já existe um local com esse nome.' });
    }

    const [result] = await pool.query(
      `INSERT INTO SF_LOCAL_ALMOXARIFADO (NOME) VALUES (?)`,
      [nome]
    );

    res.json({
      ok: true,
      id: result.insertId,
      nome
    });
  } catch (error) {
    console.error(error);

    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ erro: 'Já existe um local com esse nome.' });
    }

    res.status(500).json({ erro: 'Erro ao cadastrar local.' });
  }
});

// Consultar estoque
app.get('/api/estoque/controle/escritorio', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        base.id,
        base.codigo_item,
        base.descricao_item,
        base.unidade,
        base.qtd_entrada,
        COALESCE(tr.qtd_transferida, 0) AS qtd_transferida,
        CASE
          WHEN (base.qtd_entrada - COALESCE(tr.qtd_transferida, 0)) < 0 THEN 0
          ELSE (base.qtd_entrada - COALESCE(tr.qtd_transferida, 0))
        END AS qtd_disponivel,
        base.local,
        base.id_local_almoxarifado,
        0 AS qtd_em_pedido
      FROM (
        SELECT
          pe.produto_sistema_id AS id,
          COALESCE(p.codigo, pe.cod_produto_sistema) AS codigo_item,
          COALESCE(p.descricao, pe.descricao_produto_nf) AS descricao_item,
          COALESCE(p.unidade, pe.unidade_nf, 'UN') AS unidade,
          SUM(COALESCE(pe.qtd_nf, 0)) AS qtd_entrada,
          pe.LOCAL AS local,
          pe.ID_LOCAL_ALMOXARIFADO AS id_local_almoxarifado
        FROM SF_PRODUTO_ENTRADA pe
        LEFT JOIN SF_PRODUTOS p
          ON p.id = pe.produto_sistema_id
        WHERE pe.produto_sistema_id IS NOT NULL
          AND pe.ID_LOCAL_ALMOXARIFADO IS NOT NULL
        GROUP BY
          pe.produto_sistema_id,
          COALESCE(p.codigo, pe.cod_produto_sistema),
          COALESCE(p.descricao, pe.descricao_produto_nf),
          COALESCE(p.unidade, pe.unidade_nf, 'UN'),
          pe.LOCAL,
          pe.ID_LOCAL_ALMOXARIFADO
      ) base
      LEFT JOIN (
        SELECT
          t.ID_PRODUTO,
          t.ID_LOCAL_ORIGEM,
          SUM(COALESCE(t.QUANTIDADE, 0)) AS qtd_transferida
        FROM SF_ESTOQUE_TRANSFERENCIA t
        WHERE t.ID_PRODUTO IS NOT NULL
          AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) NOT IN ('EXCLUIDA', 'RECUSADA')
        GROUP BY
          t.ID_PRODUTO,
          t.ID_LOCAL_ORIGEM
      ) tr
        ON tr.ID_PRODUTO = base.id
       AND tr.ID_LOCAL_ORIGEM = base.id_local_almoxarifado
      ORDER BY base.codigo_item ASC, base.descricao_item ASC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao carregar estoque do escritório:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao carregar estoque do escritório.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/produto-entrada/:produtoId', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const produtoId = Number(req.params.produtoId);
    if (!produtoId) {
      return res.status(400).json({ success: false, message: 'Produto inválido.' });
    }

    const [rows] = await conn.query(
      `
      SELECT
        pe.id,
        pe.nota,
        pe.serie,
        pe.data_emissao,
        pe.data_registro,
        pe.usuario_registro,
        pe.qtd_nf,
        pe.valor_unitario_nf,
        pe.valor_total_nf,
        pe.cod_produto_nf,
        pe.descricao_produto_nf,
        pe.unidade_nf,
        pe.cod_produto_sistema,
        pe.produto_sistema_id,
        pe.local,
        pe.id_local_almoxarifado,
        pe.cnpj_emitente,
        f.razao_social AS fornecedor
      FROM SF_PRODUTO_ENTRADA pe
      LEFT JOIN SF_FORNECEDOR f ON f.id = pe.fornecedor_id
      WHERE pe.produto_sistema_id = ?
      ORDER BY pe.data_emissao DESC, pe.id DESC
      `,
      [produtoId]
    );

    return res.json({ success: true, items: rows });
  } catch (err) {
    console.error('Erro ao listar entradas:', err);
    return res.status(500).json({ success: false, message: 'Erro ao listar entradas.', error: err.message });
  } finally {
    conn.release();
  }
});

app.put('/api/estoque/produto-entrada/:id', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const id = Number(req.params.id);
    const qtd = parseDecimalBr(req.body?.qtd_nf);
    const valorUnit = parseDecimalBr(req.body?.valor_unitario_nf);
    const usuario = req.body?.usuario || req.user?.nome || req.user?.email || 'Não informado';
    const valorTotal = Number(qtd || 0) * Number(valorUnit || 0);

    if (!id) {
      return res.status(400).json({ success: false, message: 'ID da entrada inválido.' });
    }

    const [rows] = await conn.query(
      `SELECT * FROM SF_PRODUTO_ENTRADA WHERE id = ? LIMIT 1`,
      [id]
    );

    const atual = rows?.[0];
    if (!atual) {
      return res.status(404).json({ success: false, message: 'Entrada não encontrada.' });
    }

    await conn.beginTransaction();

    await conn.query(
      `
      UPDATE SF_PRODUTO_ENTRADA
      SET
        qtd_nf = ?,
        valor_unitario_nf = ?,
        valor_total_nf = ?
      WHERE id = ?
      `,
      [qtd, valorUnit, valorTotal, id]
    );

    const depois = {
      ...atual,
      qtd_nf: qtd,
      valor_unitario_nf: valorUnit,
      valor_total_nf: valorTotal
    };

    await registrarLogProdutoEntrada(conn, {
      idEntrada: id,
      acao: 'UPDATE',
      usuario,
      antes: atual,
      depois,
      observacao: 'Edição manual da entrada'
    });

    await conn.commit();

    return res.json({ success: true, message: 'Entrada atualizada com sucesso.' });
  } catch (err) {
    await conn.rollback();
    console.error('Erro ao editar entrada:', err);
    return res.status(500).json({ success: false, message: 'Erro ao editar entrada.', error: err.message });
  } finally {
    conn.release();
  }
});

app.delete('/api/estoque/produto-entrada/:id', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const id = Number(req.params.id);
    const usuario = req.body?.usuario || req.user?.nome || req.user?.email || 'Não informado';

    if (!id) {
      return res.status(400).json({ success: false, message: 'ID da entrada inválido.' });
    }

    const [rows] = await conn.query(
      `SELECT * FROM SF_PRODUTO_ENTRADA WHERE id = ? LIMIT 1`,
      [id]
    );

    const atual = rows?.[0];
    if (!atual) {
      return res.status(404).json({ success: false, message: 'Entrada não encontrada.' });
    }

    await conn.beginTransaction();

    await registrarLogProdutoEntrada(conn, {
      idEntrada: id,
      acao: 'DELETE',
      usuario,
      antes: atual,
      depois: null,
      observacao: 'Exclusão manual da entrada'
    });

    await conn.query(
      `DELETE FROM SF_PRODUTO_ENTRADA WHERE id = ? LIMIT 1`,
      [id]
    );

    await conn.commit();

    return res.json({ success: true, message: 'Entrada excluída com sucesso.' });
  } catch (err) {
    await conn.rollback();
    console.error('Erro ao excluir entrada:', err);
    return res.status(500).json({ success: false, message: 'Erro ao excluir entrada.', error: err.message });
  } finally {
    conn.release();
  }
});


async function registrarLogProdutoEntrada(conn, {
  idEntrada,
  acao,
  usuario,
  antes = null,
  depois = null,
  observacao = null
}) {
  await conn.query(
    `
    INSERT INTO SF_PRODUTO_ENTRADA_LOG (
      ID_ENTRADA,
      ACAO,
      USUARIO,
      QTD_NF_ANTES,
      QTD_NF_DEPOIS,
      VALOR_UNITARIO_NF_ANTES,
      VALOR_UNITARIO_NF_DEPOIS,
      VALOR_TOTAL_NF_ANTES,
      VALOR_TOTAL_NF_DEPOIS,
      DADOS_ANTES,
      DADOS_DEPOIS,
      OBSERVACAO
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      Number(idEntrada),
      String(acao || '').toUpperCase(),
      usuario || null,
      antes?.qtd_nf ?? null,
      depois?.qtd_nf ?? null,
      antes?.valor_unitario_nf ?? null,
      depois?.valor_unitario_nf ?? null,
      antes?.valor_total_nf ?? null,
      depois?.valor_total_nf ?? null,
      antes ? JSON.stringify(antes) : null,
      depois ? JSON.stringify(depois) : null,
      observacao || null
    ]
  );
}

// APIs transferencias

function parseDecimal(value) {
  if (value === null || value === undefined || value === '') return 0;
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0;

  const s = String(value).trim();
  if (!s) return 0;

  const normalizado = s.includes(',')
    ? s.replace(/\./g, '').replace(',', '.')
    : s;

  const n = Number(normalizado);
  return Number.isFinite(n) ? n : 0;
}

function textolivreTr(v, max = 255) {
  return String(v ?? '').trim().slice(0, max);
}

async function validarProdutoSistema(conn, idProduto) {
  const [rows] = await conn.query(
    `
    SELECT
      p.id,
      p.codigo,
      p.descricao,
      p.unidade,
      p.ativo
    FROM SF_PRODUTOS p
    WHERE p.id = ?
    LIMIT 1
    `,
    [Number(idProduto)]
  );

  return rows[0] || null;
}

async function validarLocalAlmoxarifado(conn, idLocal) {
  const [rows] = await conn.query(
    `
    SELECT
      l.ID,
      l.NOME
    FROM SF_LOCAL_ALMOXARIFADO l
    WHERE l.ID = ?
    LIMIT 1
    `,
    [Number(idLocal)]
  );

  return rows[0] || null;
}

async function validarLocalCentrocusto(conn, idLocal) {
  const [rows] = await conn.query(
    `
    SELECT
      l.ID,
      l.NOME
    FROM SF_CENTRO_CUSTO l
    WHERE l.ID = ?
    LIMIT 1
    `,
    [Number(idLocal)]
  );

  return rows[0] || null;
}

async function obterSaldoTransferivel(conn, idProduto, idLocalOrigem, ignoreTransferenciaId = null) {
  const paramsEntradas = [Number(idProduto), Number(idLocalOrigem)];
  const [rowsEntradas] = await conn.query(
    `
    SELECT COALESCE(SUM(COALESCE(pe.qtd_nf, 0)), 0) AS qtd_entrada
    FROM SF_PRODUTO_ENTRADA pe
    WHERE pe.produto_sistema_id = ?
      AND pe.ID_LOCAL_ALMOXARIFADO = ?
    `,
    paramsEntradas
  );

  const paramsRecebidas = [Number(idProduto), Number(idLocalOrigem)];
  const [rowsRecebidas] = await conn.query(
    `
    SELECT COALESCE(SUM(COALESCE(t.QUANTIDADE, 0)), 0) AS qtd_recebida
    FROM SF_ESTOQUE_TRANSFERENCIA t
    WHERE t.ID_PRODUTO = ?
      AND t.ID_LOCAL_DESTINO = ?
      AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) = 'RECEBIDO'
    `,
    paramsRecebidas
  );

  const paramsTransferidas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlTransferidas = `
    SELECT COALESCE(SUM(COALESCE(t.QUANTIDADE, 0)), 0) AS qtd_transferida
    FROM SF_ESTOQUE_TRANSFERENCIA t
    WHERE t.ID_PRODUTO = ?
      AND t.ID_LOCAL_ORIGEM = ?
      AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) IN ('AGUARDANDO_RECEBIMENTO', 'EM_TRANSITO', 'RECEBIDO')
  `;

  if (ignoreTransferenciaId) {
    sqlTransferidas += ` AND t.ID <> ?`;
    paramsTransferidas.push(Number(ignoreTransferenciaId));
  }

  const [rowsTransferidas] = await conn.query(sqlTransferidas, paramsTransferidas);

  const qtdEntrada = Number(rowsEntradas?.[0]?.qtd_entrada ?? 0);
  const qtdRecebida = Number(rowsRecebidas?.[0]?.qtd_recebida ?? 0);
  const qtdTransferida = Number(rowsTransferidas?.[0]?.qtd_transferida ?? 0);
  const saldo = qtdEntrada + qtdRecebida - qtdTransferida;

  return {
    qtdEntrada,
    qtdRecebida,
    qtdTransferida,
    saldo: saldo < 0 ? 0 : saldo
  };
}

async function inserirLogTransferencia(conn, {
  idTransferencia,
  acao,
  saldoAntes,
  quantidadeTransferida,
  saldoDepois,
  usuario,
  observacao
}) {
  await conn.query(
    `
    INSERT INTO SF_ESTOQUE_TRANSFERENCIA_LOG
      (
        ID_TRANSFERENCIA,
        ACAO,
        SALDO_ANTES,
        SALDO_DEPOIS,
        QUANTIDADE_TRANSFERIDA,
        USUARIO,
        OBSERVACAO
      )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      Number(idTransferencia),
      textolivreTr(acao, 20),
      parseDecimal(saldoAntes),
      parseDecimal(saldoDepois),
      parseDecimal(quantidadeTransferida),
      textolivreTr(usuario, 150) || null,
      textolivreTr(observacao, 255) || null
    ]
  );
}

app.get('/api/estoque/produto-entrada-log/produto/:produtoId', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const produtoId = Number(req.params.produtoId);

    if (!produtoId) {
      return res.status(400).json({ success: false, message: 'Produto inválido.' });
    }

    const produto = await validarProdutoSistema(conn, produtoId);

    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        l.ID,
        l.ID_ENTRADA,
        l.ACAO,
        l.USUARIO,
        l.DATA_ALTERACAO,
        l.QTD_NF_ANTES,
        l.QTD_NF_DEPOIS,
        l.VALOR_UNITARIO_NF_ANTES,
        l.VALOR_UNITARIO_NF_DEPOIS,
        l.VALOR_TOTAL_NF_ANTES,
        l.VALOR_TOTAL_NF_DEPOIS,
        l.OBSERVACAO,
        e.produto_sistema_id,
        e.cod_produto_nf,
        e.descricao_produto_nf,
        e.nota,
        e.serie,
        e.ID_LOCAL_ALMOXARIFADO
      FROM SF_PRODUTO_ENTRADA_LOG l
      INNER JOIN SF_PRODUTO_ENTRADA e ON e.id = l.ID_ENTRADA
      WHERE e.produto_sistema_id = ?
      ORDER BY l.DATA_ALTERACAO DESC, l.ID DESC
      `,
      [produtoId]
    );

    return res.json({
      success: true,
      produto,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao buscar histórico da entrada:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar histórico da entrada.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

app.get('/api/estoque/transferencias/saldo', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.query.idProduto);
    const idLocalOrigem = Number(req.query.idLocalOrigem);

    if (!idProduto || !idLocalOrigem) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalOrigem.'
      });
    }

    conn = await pool.getConnection();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalAlmoxarifado(conn, idLocalOrigem);
    if (!localOrigem) {
      return res.status(404).json({
        success: false,
        message: 'Local de origem não encontrado.'
      });
    }

    const saldoInfo = await obterSaldoTransferivel(conn, idProduto, idLocalOrigem);

    return res.json({
      success: true,
      produto,
      localOrigem,
      ...saldoInfo
    });
  } catch (err) {
    console.error('Erro ao calcular saldo transferível:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao calcular saldo transferível.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/transferencias', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.query.idProduto);
    const idLocalOrigem = Number(req.query.idLocalOrigem);

    if (!idProduto || !idLocalOrigem) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalOrigem.'
      });
    }

    conn = await pool.getConnection();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalAlmoxarifado(conn, idLocalOrigem);
    if (!localOrigem) {
      return res.status(404).json({
        success: false,
        message: 'Local de origem não encontrado.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        t.ID,
        t.ID_PRODUTO,
        t.ID_ENTRADA_ORIGEM,
        p.codigo AS CODIGO_PRODUTO,
        p.descricao AS DESCRICAO_PRODUTO,
        COALESCE(t.UNIDADE, p.unidade) AS UNIDADE,
        t.ID_LOCAL_ORIGEM,
        lo.NOME AS LOCAL_ORIGEM,
        t.ID_LOCAL_DESTINO,
        ld.NOME AS LOCAL_DESTINO,
        t.QUANTIDADE,
        t.OBSERVACAO,
        t.TIPO_TRANSFERENCIA,
        t.RESPONSAVEL_TRANSPORTE,
        t.RESPONSAVEL_ENTREGA,
        t.USUARIO_RECEBIMENTO,
        t.DATA_HORA_RECEBIMENTO,
        t.STATUS_TRANSFERENCIA,
        t.USUARIO_CADASTRO,
        t.DATA_CADASTRO,
        t.USUARIO_ALTERACAO,
        t.DATA_ALTERACAO
      FROM SF_ESTOQUE_TRANSFERENCIA t
      INNER JOIN SF_PRODUTOS p
        ON p.id = t.ID_PRODUTO
      LEFT JOIN SF_LOCAL_ALMOXARIFADO lo
        ON lo.ID = t.ID_LOCAL_ORIGEM
      LEFT JOIN SF_CENTRO_CUSTO ld
        ON ld.ID = t.ID_LOCAL_DESTINO
      WHERE t.ID_PRODUTO = ?
        AND t.ID_LOCAL_ORIGEM = ?
      ORDER BY t.DATA_CADASTRO DESC, t.ID DESC
      `,
      [idProduto, idLocalOrigem]
    );

    const saldoInfo = await obterSaldoTransferivel(conn, idProduto, idLocalOrigem);

    return res.json({
      success: true,
      produto,
      localOrigem,
      saldo: saldoInfo.saldo,
      qtdEntrada: saldoInfo.qtdEntrada,
      qtdTransferida: saldoInfo.qtdTransferida,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar transferências:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao listar transferências.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/estoque/transferencias', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.body.idProduto);
    const idLocalOrigem = Number(req.body.idLocalOrigem);
    const idLocalDestino = Number(req.body.idLocalDestino);
    const quantidade = parseDecimal(req.body.quantidade);
    const unidade = textolivreTr(req.body.unidade, 10);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    const tipoTransferencia = textolivreTr(req.body.tipoTransferencia, 20).toUpperCase();
    const responsavelTransporte = textolivreTr(req.body.responsavelTransporte, 150);
    const responsavelEntrega = textolivreTr(req.body.responsavelEntrega, 150);

    if (!idProduto || !idLocalOrigem || !idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto, idLocalOrigem e idLocalDestino.'
      });
    }

    if (!['LOCAL', 'EXTERNA'].includes(tipoTransferencia)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um tipo de transferência válido: LOCAL ou EXTERNA.'
      });
    }

    if (tipoTransferencia === 'EXTERNA' && (!responsavelTransporte || !responsavelEntrega)) {
      return res.status(400).json({
        success: false,
        message: 'Informe quem levará o material e para quem será entregue.'
      });
    }

    if (idLocalOrigem === idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'O local de destino deve ser diferente do local de origem.'
      });
    }

    if (!(quantidade > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida para transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Produto não encontrado na SF_PRODUTOS.' });
    }

    if (Number(produto.ativo ?? 1) !== 1) {
      await conn.rollback();
      return res.status(400).json({ success: false, message: 'O produto informado está inativo.' });
    }

    const localOrigem = await validarLocalAlmoxarifado(conn, idLocalOrigem);
    if (!localOrigem) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Local de origem não encontrado.' });
    }

    const localDestino = await validarLocalCentrocusto(conn, idLocalDestino);
    if (!localDestino) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Local de destino não encontrado.' });
    }

    const [rowsEntradaOrigem] = await conn.query(
      `
      SELECT pe.id, pe.unidade_nf, pe.ID_LOCAL_ALMOXARIFADO
      FROM SF_PRODUTO_ENTRADA pe
      WHERE pe.produto_sistema_id = ?
        AND pe.ID_LOCAL_ALMOXARIFADO = ?
      ORDER BY pe.id ASC
      LIMIT 1
      `,
      [idProduto, idLocalOrigem]
    );

    const entradaOrigem = rowsEntradaOrigem[0] || null;
    if (!entradaOrigem) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Não existe entrada desse produto nesse local para transferir.'
      });
    }

    const saldoInfo = await obterSaldoTransferivel(conn, idProduto, idLocalOrigem);
    const saldoAntes = saldoInfo.saldo;

    if (quantidade > saldoAntes) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Quantidade excede o saldo disponível (${saldoAntes}).`
      });
    }

    const statusTransferencia =
      tipoTransferencia === 'LOCAL'
        ? 'AGUARDANDO_RECEBIMENTO'
        : 'EM_TRANSITO';

    const [result] = await conn.query(
      `
      INSERT INTO SF_ESTOQUE_TRANSFERENCIA
        (
          ID_PRODUTO,
          ID_ENTRADA_ORIGEM,
          ID_LOCAL_ORIGEM,
          ID_LOCAL_DESTINO,
          QUANTIDADE,
          UNIDADE,
          OBSERVACAO,
          TIPO_TRANSFERENCIA,
          RESPONSAVEL_TRANSPORTE,
          RESPONSAVEL_ENTREGA,
          STATUS_TRANSFERENCIA,
          USUARIO_CADASTRO
        )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idProduto,
        Number(entradaOrigem.id),
        idLocalOrigem,
        idLocalDestino,
        quantidade,
        unidade || produto.unidade || entradaOrigem.unidade_nf || null,
        observacao || null,
        tipoTransferencia,
        tipoTransferencia === 'EXTERNA' ? responsavelTransporte : null,
        tipoTransferencia === 'EXTERNA' ? responsavelEntrega : null,
        statusTransferencia,
        usuario
      ]
    );

    const idTransferencia = result.insertId;
    const saldoDepois = saldoAntes - quantidade;

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'CRIACAO',
      saldoAntes,
      quantidadeTransferida: quantidade,
      saldoDepois,
      usuario,
      observacao: `Tipo: ${tipoTransferencia}; Status inicial: ${statusTransferencia}${observacao ? `; Obs: ${observacao}` : ''}`
    });

    await conn.commit();

    return res.json({
      success: true,
      id: idTransferencia,
      statusTransferencia,
      message: 'Transferência registrada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao registrar transferência:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/estoque/transferencias/:id', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const idLocalDestino = Number(req.body.idLocalDestino);
    const quantidadeNova = parseDecimal(req.body.quantidade);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    if (!idTransferencia) {
      return res.status(400).json({
        success: false,
        message: 'Informe o ID da transferência.'
      });
    }

    if (!idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'Informe o local de destino.'
      });
    }

    if (!(quantidadeNova > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsAtual] = await conn.query(
      `
      SELECT *
      FROM SF_ESTOQUE_TRANSFERENCIA
      WHERE ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const atual = rowsAtual[0];

    if (!atual) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    if (atual.STATUS_TRANSFERENCIA !== 'AGUARDANDO_RECEBIMENTO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Apenas transferências aguardando recebimento podem ser editadas.'
      });
    }


    const produto = await validarProdutoSistema(conn, atual.ID_PRODUTO);
    if (!produto) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Produto vinculado à transferência não foi encontrado.'
      });
    }

    const localOrigem = await validarLocalAlmoxarifado(conn, atual.ID_LOCAL_ORIGEM);
    if (!localOrigem) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Local de origem da transferência não encontrado.'
      });
    }

    const localDestino = await validarLocalCentrocusto(conn, idLocalDestino);
    if (!localDestino) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Local de destino não encontrado.'
      });
    }

    if (Number(atual.ID_LOCAL_ORIGEM) === idLocalDestino) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O local de destino deve ser diferente do local de origem.'
      });
    }

    const saldoInfo = await obterSaldoTransferivel(
      conn,
      atual.ID_PRODUTO,
      atual.ID_LOCAL_ORIGEM,
      idTransferencia
    );

    const quantidadeAtual = Number(atual.QUANTIDADE ?? 0);
    const saldoAntes = saldoInfo.saldo + quantidadeAtual;
    const saldoMaximoPermitido = saldoInfo.saldo + quantidadeAtual;

    if (quantidadeNova > saldoMaximoPermitido) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Quantidade excede o saldo disponível (${saldoMaximoPermitido}).`
      });
    }

    await conn.query(
      `
      UPDATE SF_ESTOQUE_TRANSFERENCIA
      SET
        ID_LOCAL_DESTINO = ?,
        QUANTIDADE = ?,
        OBSERVACAO = ?,
        UNIDADE = ?,
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW()
      WHERE ID = ?
      `,
      [
        idLocalDestino,
        quantidadeNova,
        observacao || null,
        atual.UNIDADE || produto.unidade || null,
        usuario,
        idTransferencia
      ]
    );

    const saldoDepois = saldoAntes - quantidadeNova;

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'EDICAO',
      saldoAntes,
      quantidadeTransferida: quantidadeNova,
      saldoDepois,
      usuario,
      observacao
    });

    await conn.commit();

    return res.json({
      success: true,
      message: 'Transferência atualizada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao editar transferência:', err);

    try { if (conn) await conn.rollback(); } catch {}

    return res.status(500).json({
      success: false,
      message: 'Erro ao editar transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.delete('/api/estoque/transferencias/:id', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const usuario = textolivreTr(req.body?.usuario || req.query?.usuario, 150) || 'SISTEMA';
    const observacao = textolivreTr(req.body?.observacao || 'Exclusão de transferência.', 255);

    if (!idTransferencia) {
      return res.status(400).json({
        success: false,
        message: 'Informe o ID da transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsAtual] = await conn.query(
      `
      SELECT *
      FROM SF_ESTOQUE_TRANSFERENCIA
      WHERE ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const atual = rowsAtual[0];

    if (!atual) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    if (atual.STATUS_TRANSFERENCIA !== 'AGUARDANDO_RECEBIMENTO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Apenas transferências aguardando recebimento podem ser excluídas.'
      });
    }


    const saldoInfo = await obterSaldoTransferivel(
      conn,
      atual.ID_PRODUTO,
      atual.ID_LOCAL_ORIGEM,
      idTransferencia
    );

    const saldoAntes = saldoInfo.saldo;
    const saldoDepois = saldoAntes + Number(atual.QUANTIDADE ?? 0);

    await conn.query(
      `
      UPDATE SF_ESTOQUE_TRANSFERENCIA
      SET
        STATUS_TRANSFERENCIA = 'EXCLUIDA',
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW(),
        OBSERVACAO = CASE
          WHEN OBSERVACAO IS NULL OR OBSERVACAO = '' THEN ?
          ELSE CONCAT(OBSERVACAO, ' | ', ?)
        END
      WHERE ID = ?
      `,
      [usuario, observacao, observacao, idTransferencia]
    );

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'EXCLUSAO',
      saldoAntes,
      quantidadeTransferida: atual.QUANTIDADE,
      saldoDepois,
      usuario,
      observacao
    });

    await conn.commit();

    return res.json({
      success: true,
      message: 'Transferência excluída com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao excluir transferência:', err);

    try { if (conn) await conn.rollback(); } catch {}

    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/transferencias/:id/logs', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);

    if (!idTransferencia) {
      return res.status(400).json({
        success: false,
        message: 'Informe o ID da transferência.'
      });
    }

    conn = await pool.getConnection();

    const [rows] = await conn.query(
      `
      SELECT
        l.ID,
        l.ID_TRANSFERENCIA,
        l.ACAO,
        l.SALDO_ANTES,
        l.QUANTIDADE_TRANSFERIDA,
        l.SALDO_DEPOIS,
        l.USUARIO,
        l.OBSERVACAO,
        l.DATA_HORA
      FROM SF_ESTOQUE_TRANSFERENCIA_LOG l
      WHERE l.ID_TRANSFERENCIA = ?
      ORDER BY l.DATA_HORA DESC, l.ID DESC
      `,
      [idTransferencia]
    );

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar logs da transferência:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao listar logs da transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/estoque/transferencias/:id/recebimento', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';
    const observacao = textolivreTr(req.body.observacao, 255);



    if (!idTransferencia) {


      return res.status(400).json({
        success: false,
        message: 'Informe o ID da transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsTransferencia] = await conn.query(
      `
      SELECT
        t.*,
        ld.NOME AS LOCAL_DESTINO_NOME
      FROM SF_ESTOQUE_TRANSFERENCIA t
      LEFT JOIN SF_CENTRO_CUSTO ld
        ON ld.ID = t.ID_LOCAL_DESTINO
      WHERE t.ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const transferencia = rowsTransferencia[0] || null;


    if (!transferencia) {
      await conn.rollback();

      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    const statusTransferencia = String(
      transferencia.STATUS_TRANSFERENCIA ?? transferencia.STATUSTRANSFERENCIA ?? ''
    ).trim().toUpperCase();



    if (!['EM_TRANSITO', 'AGUARDANDO_RECEBIMENTO'].includes(statusTransferencia)) {
      await conn.rollback();

      return res.status(400).json({
        success: false,
        message: 'Somente transferências em trânsito ou aguardando recebimento podem ser recebidas.'
      });
    }

    const [rowsUsuario] = await conn.query(
      `
      SELECT
        u.*
      FROM SF_USUARIO u
      WHERE UPPER(TRIM(u.nome)) = UPPER(TRIM(?))
      LIMIT 1
      `,
      [usuario]
    );

    const usuarioDb = rowsUsuario[0] || null;



    if (!usuarioDb) {
      await conn.rollback();

      return res.status(403).json({
        success: false,
        message: 'Usuário logado não encontrado na SF_USUARIO.'
      });
    }

    const centroCustoUsuario = String(
      usuarioDb.LOCAL_TRABALHO ?? usuarioDb.LOCAL_TRABALHO ?? ''
    ).trim().toUpperCase();

    const localDestinoNome = String(
      transferencia.LOCAL_DESTINO_NOME ?? ''
    ).trim().toUpperCase();



    if (!centroCustoUsuario || centroCustoUsuario !== localDestinoNome) {
      await conn.rollback();



      return res.status(403).json({
        success: false,
        message: 'O usuário logado não pertence ao centro de custo do local de destino da transferência.'
      });
    }


    await conn.query(
      `
      UPDATE SF_ESTOQUE_TRANSFERENCIA
      SET
        STATUS_TRANSFERENCIA = 'RECEBIDO',
        USUARIO_RECEBIMENTO = ?,
        DATA_HORA_RECEBIMENTO = NOW(),
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW()
      WHERE ID = ?
      `,
      [usuario, usuario, idTransferencia]
    );

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'RECEBIMENTO',
      saldoAntes: 0,
      quantidadeTransferida: Number(transferencia.QUANTIDADE ?? 0),
      saldoDepois: 0,
      usuario,
      observacao: observacao || `Recebimento confirmado por ${usuario}.`
    });


    await conn.commit();


    return res.json({
      success: true,
      message: 'Recebimento da transferência registrado com sucesso.'
    });
  } catch (err) {
    console.error('[RECEBIMENTO] Erro ao registrar recebimento da transferência:', {
      message: err.message,
      stack: err.stack
    });

    try {
      if (conn) await conn.rollback();
    } catch (rollbackErr) {
      console.error('[RECEBIMENTO] Erro no rollback:', {
        message: rollbackErr.message,
        stack: rollbackErr.stack
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar recebimento da transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();

  }
});

app.post('/api/estoque/transferencias/:id/recusa', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';
    const observacao = textolivreTr(req.body.observacao, 255);



    if (!idTransferencia) {


      return res.status(400).json({
        success: false,
        message: 'Informe o ID da transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsTransferencia] = await conn.query(
      `
      SELECT
        t.*,
        ld.NOME AS LOCAL_DESTINO_NOME
      FROM SF_ESTOQUE_TRANSFERENCIA t
      LEFT JOIN SF_CENTRO_CUSTO ld
        ON ld.ID = t.ID_LOCAL_DESTINO
      WHERE t.ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const transferencia = rowsTransferencia[0] || null;


    if (!transferencia) {
      await conn.rollback();

      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    const statusTransferencia = String(
      transferencia.STATUS_TRANSFERENCIA ?? transferencia.STATUSTRANSFERENCIA ?? ''
    ).trim().toUpperCase();



    if (!['EM_TRANSITO', 'AGUARDANDO_RECEBIMENTO'].includes(statusTransferencia)) {
      await conn.rollback();

      return res.status(400).json({
        success: false,
        message: 'Somente transferências em trânsito ou aguardando recebimento podem ser recebidas.'
      });
    }

    const [rowsUsuario] = await conn.query(
      `
      SELECT
        u.*
      FROM SF_USUARIO u
      WHERE UPPER(TRIM(u.nome)) = UPPER(TRIM(?))
      LIMIT 1
      `,
      [usuario]
    );

    const usuarioDb = rowsUsuario[0] || null;



    if (!usuarioDb) {
      await conn.rollback();

      return res.status(403).json({
        success: false,
        message: 'Usuário logado não encontrado na SF_USUARIO.'
      });
    }

    const centroCustoUsuario = String(
      usuarioDb.LOCAL_TRABALHO ?? usuarioDb.LOCAL_TRABALHO ?? ''
    ).trim().toUpperCase();

    const localDestinoNome = String(
      transferencia.LOCAL_DESTINO_NOME ?? ''
    ).trim().toUpperCase();



    if (!centroCustoUsuario || centroCustoUsuario !== localDestinoNome) {
      await conn.rollback();



      return res.status(403).json({
        success: false,
        message: 'O usuário logado não pertence ao centro de custo do local de destino da transferência.'
      });
    }


    await conn.query(
      `
      UPDATE SF_ESTOQUE_TRANSFERENCIA
      SET
        STATUS_TRANSFERENCIA = 'RECUSADA',
        USUARIO_RECEBIMENTO = ?,
        DATA_HORA_RECEBIMENTO = NOW(),
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW()
      WHERE ID = ?
      `,
      [usuario, usuario, idTransferencia]
    );

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'RECUSA',
      saldoAntes: 0,
      quantidadeTransferida: Number(transferencia.QUANTIDADE ?? 0),
      saldoDepois: 0,
      usuario,
      observacao: observacao || `Recusa realizada por ${usuario}.`
    });


    await conn.commit();


    return res.json({
      success: true,
      message: 'Recusa da transferência registrada com sucesso.'
    });
  } catch (err) {
    console.error('[RECUSA] Erro ao registrar recusa da transferência:', {
      message: err.message,
      stack: err.stack
    });

    try {
      if (conn) await conn.rollback();
    } catch (rollbackErr) {
      console.error('[RECUSA] Erro no rollback:', {
        message: rollbackErr.message,
        stack: rollbackErr.stack
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar recusa da transferência.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();

  }
});

// centro de custo
app.get('/api/estoque/centro-custo', async (req, res) => {
  let conn;

  try {
    const usuario = textolivreTr(req.query.usuario, 150) || 'SISTEMA';

    conn = await pool.getConnection();

    const [rowsUsuario] = await conn.query(
      `
      SELECT
        u.ID,
        u.nome,
        u.LOCAL_TRABALHO
      FROM SF_USUARIO u
      WHERE UPPER(TRIM(u.nome)) = UPPER(TRIM(?))
      LIMIT 1
      `,
      [usuario]
    );

    const usuarioDb = rowsUsuario[0] || null;

    if (!usuarioDb) {
      return res.status(404).json({
        success: false,
        message: 'Usuário logado não encontrado na SF_USUARIO.'
      });
    }

    const centroCustoUsuario = String(usuarioDb.LOCAL_TRABALHO ?? '').trim().toUpperCase();

    if (!centroCustoUsuario) {
      return res.status(400).json({
        success: false,
        message: 'O usuário logado não possui centro de custo vinculado.'
      });
    }

    const [rowsCentro] = await conn.query(
      `
      SELECT ID, NOME
      FROM SF_CENTRO_CUSTO
      WHERE UPPER(TRIM(NOME)) = ?
      LIMIT 1
      `,
      [centroCustoUsuario]
    );

    const centro = rowsCentro[0] || null;

    if (!centro) {
      return res.status(404).json({
        success: false,
        message: 'Centro de custo não encontrado.'
      });
    }

    const [notificacoesPendentes] = await conn.query(
      `
      SELECT
        t.ID,
        t.ID_PRODUTO,
        t.ID_ENTRADA_ORIGEM,
        p.codigo AS CODIGO_PRODUTO,
        p.descricao AS DESCRICAO_PRODUTO,
        COALESCE(t.UNIDADE, p.unidade, 'UN') AS UNIDADE,
        t.ID_LOCAL_ORIGEM,
        COALESCE(loa.NOME, lot.NOME) AS LOCAL_ORIGEM,
        t.ID_LOCAL_DESTINO,
        ld.NOME AS LOCAL_DESTINO,
        t.QUANTIDADE,
        t.OBSERVACAO,
        t.TIPO_TRANSFERENCIA,
        t.RESPONSAVEL_TRANSPORTE,
        t.RESPONSAVEL_ENTREGA,
        t.USUARIO_RECEBIMENTO,
        t.DATA_HORA_RECEBIMENTO,
        t.STATUS_TRANSFERENCIA,
        t.USUARIO_CADASTRO,
        t.DATA_CADASTRO,
        t.USUARIO_ALTERACAO,
        t.DATA_ALTERACAO
      FROM SF_ESTOQUE_TRANSFERENCIA t
      INNER JOIN SF_PRODUTOS p
        ON p.id = t.ID_PRODUTO
      LEFT JOIN SF_LOCAL_ALMOXARIFADO loa
        ON loa.ID = t.ID_LOCAL_ORIGEM
      LEFT JOIN SF_CENTRO_CUSTO lot
        ON lot.ID = t.ID_LOCAL_ORIGEM
      LEFT JOIN SF_CENTRO_CUSTO ld
        ON ld.ID = t.ID_LOCAL_DESTINO
      WHERE t.ID_LOCAL_DESTINO = ?
        AND t.STATUS_TRANSFERENCIA IN ('AGUARDANDO_RECEBIMENTO', 'EM_TRANSITO')
      ORDER BY t.DATA_CADASTRO DESC, t.ID DESC
      `,
      [centro.ID]
    );

    const [items] = await conn.query(
      `
      SELECT
        p.id AS ID_PRODUTO,
        p.codigo AS CODIGO_PRODUTO,
        p.descricao AS DESCRICAO_PRODUTO,
        COALESCE(p.unidade, 'UN') AS UNIDADE,
        centro.ID AS ID_LOCAL_DESTINO,
        centro.NOME AS LOCAL_DESTINO,
        COALESCE(rec.qtd_recebida, 0) AS QTD_RECEBIDA,
        COALESCE(env.qtd_enviada, 0) AS QTD_ENVIADA,
        COALESCE(pend.qtd_transferida_nao_recebida, 0) AS QTD_TRANSFERIDA_NAO_RECEBIDA,
        CASE
          WHEN COALESCE(rec.qtd_recebida, 0) - COALESCE(env.qtd_enviada, 0) < 0 THEN 0
          ELSE COALESCE(rec.qtd_recebida, 0) - COALESCE(env.qtd_enviada, 0)
        END AS QUANTIDADE
      FROM SF_PRODUTOS p
      LEFT JOIN (
        SELECT
          t.ID_PRODUTO,
          SUM(COALESCE(t.QUANTIDADE, 0)) AS qtd_recebida
        FROM SF_ESTOQUE_TRANSFERENCIA t
        WHERE t.ID_LOCAL_DESTINO = ?
          AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) = 'RECEBIDO'
        GROUP BY t.ID_PRODUTO
      ) rec ON rec.ID_PRODUTO = p.id
      LEFT JOIN (
        SELECT
          t.ID_PRODUTO,
          SUM(COALESCE(t.QUANTIDADE, 0)) AS qtd_enviada
        FROM SF_ESTOQUE_TRANSFERENCIA t
        WHERE t.ID_LOCAL_ORIGEM = ?
          AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) IN ('AGUARDANDO_RECEBIMENTO', 'EM_TRANSITO', 'RECEBIDO')
        GROUP BY t.ID_PRODUTO
      ) env ON env.ID_PRODUTO = p.id
      LEFT JOIN (
        SELECT
          t.ID_PRODUTO,
          SUM(COALESCE(t.QUANTIDADE, 0)) AS qtd_transferida_nao_recebida
        FROM SF_ESTOQUE_TRANSFERENCIA t
        WHERE t.ID_LOCAL_ORIGEM = ?
          AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) IN ('AGUARDANDO_RECEBIMENTO', 'EM_TRANSITO')
        GROUP BY t.ID_PRODUTO
      ) pend ON pend.ID_PRODUTO = p.id
      CROSS JOIN (
        SELECT ID, NOME
        FROM SF_CENTRO_CUSTO
        WHERE ID = ?
      ) centro
      WHERE EXISTS (
        SELECT 1
        FROM SF_ESTOQUE_TRANSFERENCIA t
        WHERE t.ID_PRODUTO = p.id
          AND (t.ID_LOCAL_DESTINO = ? OR t.ID_LOCAL_ORIGEM = ?)
      )
      ORDER BY p.codigo ASC, p.descricao ASC
      `,
      [centro.ID, centro.ID, centro.ID, centro.ID, centro.ID, centro.ID]
    );

    return res.json({
      success: true,
      usuario,
      centroCusto: centroCustoUsuario,
      notificacoesPendentes,
      items
    });
  } catch (err) {
    console.error('Erro ao carregar estoque do centro de custo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao carregar estoque do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/locais-centrocusto', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT ID, NOME
      FROM SF_CENTRO_CUSTO
      ORDER BY NOME ASC
    `);

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao listar locais.' });
  }
});

app.post('/api/locais-centrocusto', async (req, res) => {
  try {
    const nome = String(req.body?.nome || '').trim().toUpperCase();

    if (!nome) {
      return res.status(400).json({ erro: 'Informe o nome do local.' });
    }

    const [existente] = await pool.query(
      `SELECT ID FROM SF_CENTRO_CUSTO WHERE UPPER(NOME) = ? LIMIT 1`,
      [nome]
    );

    if (existente.length) {
      return res.status(409).json({ erro: 'Já existe um local com esse nome.' });
    }

    const [result] = await pool.query(
      `INSERT INTO SF_CENTRO_CUSTO (NOME) VALUES (?)`,
      [nome]
    );

    res.json({
      ok: true,
      id: result.insertId,
      nome
    });
  } catch (error) {
    console.error(error);

    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ erro: 'Já existe um local com esse nome.' });
    }

    res.status(500).json({ erro: 'Erro ao cadastrar local.' });
  }
});

async function obterSaldoCentroCusto(conn, idProduto, idLocalOrigem, ignoreTransferenciaId = null) {
  const paramsRecebidas = [Number(idProduto), Number(idLocalOrigem)];
  const [rowsRecebidas] = await conn.query(
    `
    SELECT COALESCE(SUM(COALESCE(t.QUANTIDADE, 0)), 0) AS qtd_recebida
    FROM SF_ESTOQUE_TRANSFERENCIA t
    WHERE t.ID_PRODUTO = ?
      AND t.ID_LOCAL_DESTINO = ?
      AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) = 'RECEBIDO'
    `,
    paramsRecebidas
  );

  const paramsEnviadas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlEnviadas = `
    SELECT COALESCE(SUM(COALESCE(t.QUANTIDADE, 0)), 0) AS qtd_enviada
    FROM SF_ESTOQUE_TRANSFERENCIA t
    WHERE t.ID_PRODUTO = ?
      AND t.ID_LOCAL_ORIGEM = ?
      AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) IN ('AGUARDANDO_RECEBIMENTO', 'EM_TRANSITO', 'RECEBIDO')
  `;

  if (ignoreTransferenciaId) {
    sqlEnviadas += ' AND t.ID <> ?';
    paramsEnviadas.push(Number(ignoreTransferenciaId));
  }

  const [rowsEnviadas] = await conn.query(sqlEnviadas, paramsEnviadas);

  const qtdRecebida = Number(rowsRecebidas?.[0]?.qtd_recebida ?? 0);
  const qtdEnviada = Number(rowsEnviadas?.[0]?.qtd_enviada ?? 0);
  const saldo = qtdRecebida - qtdEnviada;

  return {
    qtdRecebida,
    qtdEnviada,
    saldo: saldo < 0 ? 0 : saldo
  };
}

app.get('/api/estoque/centro-custo/saldo', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.query.idProduto);
    const idLocalOrigem = Number(req.query.idLocalOrigem);

    if (!idProduto || !idLocalOrigem) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalOrigem.'
      });
    }

    conn = await pool.getConnection();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalCentrocusto(conn, idLocalOrigem);
    if (!localOrigem) {
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de origem não encontrado.'
      });
    }

    const saldoInfo = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem);

    return res.json({
      success: true,
      produto,
      localOrigem,
      ...saldoInfo
    });
  } catch (err) {
    console.error('Erro ao calcular saldo do centro de custo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao calcular saldo do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/centro-custo/transferencias', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.query.idProduto);
    const idLocalOrigem = Number(req.query.idLocalOrigem);

    if (!idProduto || !idLocalOrigem) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalOrigem.'
      });
    }

    conn = await pool.getConnection();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalCentrocusto(conn, idLocalOrigem);
    if (!localOrigem) {
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de origem não encontrado.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        t.ID,
        t.ID_PRODUTO,
        t.ID_ENTRADA_ORIGEM,
        p.codigo AS CODIGO_PRODUTO,
        p.descricao AS DESCRICAO_PRODUTO,
        COALESCE(t.UNIDADE, p.unidade) AS UNIDADE,
        t.ID_LOCAL_ORIGEM,
        lo.NOME AS LOCAL_ORIGEM,
        t.ID_LOCAL_DESTINO,
        ld.NOME AS LOCAL_DESTINO,
        t.QUANTIDADE,
        t.OBSERVACAO,
        t.TIPO_TRANSFERENCIA,
        t.RESPONSAVEL_TRANSPORTE,
        t.RESPONSAVEL_ENTREGA,
        t.USUARIO_RECEBIMENTO,
        t.DATA_HORA_RECEBIMENTO,
        t.STATUS_TRANSFERENCIA,
        t.USUARIO_CADASTRO,
        t.DATA_CADASTRO,
        t.USUARIO_ALTERACAO,
        t.DATA_ALTERACAO
      FROM SF_ESTOQUE_TRANSFERENCIA t
      INNER JOIN SF_PRODUTOS p
        ON p.id = t.ID_PRODUTO
      LEFT JOIN SF_CENTRO_CUSTO lo
        ON lo.ID = t.ID_LOCAL_ORIGEM
      LEFT JOIN SF_CENTRO_CUSTO ld
        ON ld.ID = t.ID_LOCAL_DESTINO
      WHERE t.ID_PRODUTO = ?
        AND t.ID_LOCAL_ORIGEM = ?
      ORDER BY t.DATA_CADASTRO DESC, t.ID DESC
      `,
      [idProduto, idLocalOrigem]
    );

    const saldoInfo = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem);

    return res.json({
      success: true,
      produto,
      localOrigem,
      saldo: saldoInfo.saldo,
      qtdRecebida: saldoInfo.qtdRecebida,
      qtdEnviada: saldoInfo.qtdEnviada,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar transferências do centro de custo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar transferências do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/estoque/centro-custo/transferencias', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.body.idProduto);
    const idLocalOrigem = Number(req.body.idLocalOrigem);
    const idLocalDestino = Number(req.body.idLocalDestino);
    const quantidade = parseDecimal(req.body.quantidade);
    const unidade = textolivreTr(req.body.unidade, 10);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    if (!idProduto || !idLocalOrigem || !idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto, idLocalOrigem e idLocalDestino.'
      });
    }

    if (idLocalOrigem === idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'O local de destino deve ser diferente do local de origem.'
      });
    }

    if (!(quantidade > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida para transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalCentrocusto(conn, idLocalOrigem);
    if (!localOrigem) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de origem não encontrado.'
      });
    }

    const localDestino = await validarLocalCentrocusto(conn, idLocalDestino);
    if (!localDestino) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de destino não encontrado.'
      });
    }

    const saldoInfo = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem);
    const saldoAntes = saldoInfo.saldo;

    if (quantidade > saldoAntes) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Quantidade excede o saldo disponível (${saldoAntes}).`
      });
    }

    const [result] = await conn.query(
      `
      INSERT INTO SF_ESTOQUE_TRANSFERENCIA
        (
          ID_PRODUTO,
          ID_ENTRADA_ORIGEM,
          ID_LOCAL_ORIGEM,
          ID_LOCAL_DESTINO,
          QUANTIDADE,
          UNIDADE,
          OBSERVACAO,
          TIPO_TRANSFERENCIA,
          RESPONSAVEL_TRANSPORTE,
          RESPONSAVEL_ENTREGA,
          STATUS_TRANSFERENCIA,
          USUARIO_CADASTRO
        )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idProduto,
        null,
        idLocalOrigem,
        idLocalDestino,
        quantidade,
        unidade || produto.unidade || null,
        observacao || null,
        'LOCAL',
        null,
        null,
        'AGUARDANDO_RECEBIMENTO',
        usuario
      ]
    );

    const idTransferencia = result.insertId;
    const saldoDepois = saldoAntes - quantidade;

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'CRIACAO',
      saldoAntes,
      quantidadeTransferida: quantidade,
      saldoDepois,
      usuario,
      observacao: observacao || 'Transferência entre centros de custo.'
    });

    await conn.commit();

    return res.json({
      success: true,
      id: idTransferencia,
      message: 'Transferência entre centros de custo registrada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao registrar transferência centro de custo:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar transferência do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/estoque/centro-custo/transferencias/:id', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const idProduto = Number(req.body.idProduto);
    const idLocalOrigem = Number(req.body.idLocalOrigem);
    const idLocalDestino = Number(req.body.idLocalDestino);
    const quantidade = parseDecimal(req.body.quantidade);
    const unidade = textolivreTr(req.body.unidade, 10);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    if (!idTransferencia || !idProduto || !idLocalOrigem || !idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'Informe id, idProduto, idLocalOrigem e idLocalDestino.'
      });
    }

    if (idLocalOrigem === idLocalDestino) {
      return res.status(400).json({
        success: false,
        message: 'O local de destino deve ser diferente do local de origem.'
      });
    }

    if (!(quantidade > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida para transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsTransferencia] = await conn.query(
      `
      SELECT *
      FROM SF_ESTOQUE_TRANSFERENCIA
      WHERE ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const transferencia = rowsTransferencia[0] || null;

    if (!transferencia) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    if (Number(transferencia.ID_PRODUTO) !== idProduto || Number(transferencia.ID_LOCAL_ORIGEM) !== idLocalOrigem) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'A transferência informada não pertence ao produto/local de origem enviado.'
      });
    }

    const statusAtual = String(transferencia.STATUS_TRANSFERENCIA ?? '').trim().toUpperCase();
    if (statusAtual !== 'AGUARDANDO_RECEBIMENTO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente transferências aguardando recebimento podem ser editadas.'
      });
    }

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    const localOrigem = await validarLocalCentrocusto(conn, idLocalOrigem);
    if (!localOrigem) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de origem não encontrado.'
      });
    }

    const localDestino = await validarLocalCentrocusto(conn, idLocalDestino);
    if (!localDestino) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Centro de custo de destino não encontrado.'
      });
    }

    const saldoInfo = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem, idTransferencia);
    const saldoAntes = Number(saldoInfo.saldo ?? 0);
    const quantidadeAnterior = Number(transferencia.QUANTIDADE ?? 0);
    const saldoDisponivelEdicao = saldoAntes + quantidadeAnterior;

    if (quantidade > saldoDisponivelEdicao) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Quantidade excede o saldo disponível (${saldoDisponivelEdicao}).`
      });
    }

    await conn.query(
      `
      UPDATE SF_ESTOQUE_TRANSFERENCIA
      SET
        ID_LOCAL_DESTINO = ?,
        QUANTIDADE = ?,
        UNIDADE = ?,
        OBSERVACAO = ?,
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW()
      WHERE ID = ?
      `,
      [
        idLocalDestino,
        quantidade,
        unidade || transferencia.UNIDADE || produto.unidade || null,
        observacao || null,
        usuario,
        idTransferencia
      ]
    );

    const saldoDepois = saldoDisponivelEdicao - quantidade;

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'EDICAO',
      saldoAntes: saldoDisponivelEdicao,
      quantidadeTransferida: quantidade,
      saldoDepois,
      usuario,
      observacao: observacao || 'Transferência entre centros de custo alterada.'
    });

    await conn.commit();

    return res.json({
      success: true,
      id: idTransferencia,
      message: 'Transferência entre centros de custo alterada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao editar transferência centro de custo:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao editar transferência do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.delete('/api/estoque/centro-custo/transferencias/:id', async (req, res) => {
  let conn;

  try {
    const idTransferencia = Number(req.params.id);
    const usuario = textolivreTr(req.body?.usuario, 150) || 'SISTEMA';
    const observacao = textolivreTr(req.body?.observacao, 255);

    if (!idTransferencia) {
      return res.status(400).json({
        success: false,
        message: 'Informe o id da transferência.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsTransferencia] = await conn.query(
      `
      SELECT *
      FROM SF_ESTOQUE_TRANSFERENCIA
      WHERE ID = ?
      LIMIT 1
      `,
      [idTransferencia]
    );

    const transferencia = rowsTransferencia[0] || null;

    if (!transferencia) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Transferência não encontrada.'
      });
    }

    const statusAtual = String(transferencia.STATUS_TRANSFERENCIA ?? '').trim().toUpperCase();
    if (statusAtual !== 'AGUARDANDO_RECEBIMENTO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente transferências aguardando recebimento podem ser excluídas.'
      });
    }

    const idProduto = Number(transferencia.ID_PRODUTO);
    const idLocalOrigem = Number(transferencia.ID_LOCAL_ORIGEM);
    const quantidade = Number(transferencia.QUANTIDADE ?? 0);

    const saldoInfo = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem, idTransferencia);
    const saldoAntes = Number(saldoInfo.saldo ?? 0) + quantidade;
    const saldoDepois = Number(saldoInfo.saldo ?? 0);

    await inserirLogTransferencia(conn, {
      idTransferencia,
      acao: 'EXCLUSAO',
      saldoAntes,
      quantidadeTransferida: quantidade,
      saldoDepois,
      usuario,
      observacao: observacao || 'Transferência entre centros de custo excluída.'
    });

    await conn.query(
      `
      DELETE FROM SF_ESTOQUE_TRANSFERENCIA
      WHERE ID = ?
      `,
      [idTransferencia]
    );

    await conn.commit();

    return res.json({
      success: true,
      id: idTransferencia,
      message: 'Transferência entre centros de custo excluída com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao excluir transferência centro de custo:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir transferência do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// emails

// PUT Destinatário (editar)
app.put('/api/emails/destinatarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { ID_REMETENTE, EMAIL_DESTINATARIO, NOME_DESTINATARIO } = req.body;
    
    const [result] = await pool.query(
      `UPDATE SF_EMAIL_DESTINATARIOS 
       SET ID_REMETENTE = ?, EMAIL_DESTINATARIO = ?, NOME_DESTINATARIO = ? 
       WHERE ID = ?`,
      [
        Number(ID_REMETENTE),
        EMAIL_DESTINATARIO.toLowerCase().trim(),
        NOME_DESTINATARIO?.trim() || null,
        id
      ]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Destinatário não encontrado' });
    }
    
    res.json({ success: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Destinatário já cadastrado para este remetente' });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE Destinatário (desativar)
app.delete('/api/emails/destinatarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [result] = await pool.query(
      `UPDATE SF_EMAIL_DESTINATARIOS SET ATIVO = 0 WHERE ID = ?`,
      [id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Destinatário não encontrado' });
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST Novo/Editar Remetente
app.post('/api/emails/remetentes', async (req, res) => {
  try {
    const { EMAIL, NOME } = req.body;
    const [result] = await pool.query(
      `INSERT INTO SF_EMAIL_REMETENTE (EMAIL, NOME, ATIVO) VALUES (?, ?, 1)`,
      [EMAIL.toLowerCase().trim(), NOME?.trim() || null]
    );
    res.status(201).json({ success: true, id: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Email já cadastrado' });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/api/emails/remetentes/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { EMAIL, NOME } = req.body;
    const [result] = await pool.query(
      `UPDATE SF_EMAIL_REMETENTE SET EMAIL = ?, NOME = ? WHERE ID = ?`,
      [EMAIL.toLowerCase().trim(), NOME?.trim() || null, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Remetente não encontrado' });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/emails/remetentes/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query(`UPDATE SF_EMAIL_REMETENTE SET ATIVO = 0 WHERE ID = ?`, [id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST Destinatário (igual, mas com ID_REMETENTE)
app.post('/api/emails/destinatarios', async (req, res) => {
  try {
    const { ID_REMETENTE, EMAIL_DESTINATARIO, NOME_DESTINATARIO } = req.body;
    const [result] = await pool.query(
      `INSERT INTO SF_EMAIL_DESTINATARIOS (ID_REMETENTE, EMAIL_DESTINATARIO, NOME_DESTINATARIO, ATIVO) 
       VALUES (?, ?, ?, 1)`,
      [Number(ID_REMETENTE), EMAIL_DESTINATARIO.toLowerCase().trim(), NOME_DESTINATARIO?.trim() || null]
    );
    res.status(201).json({ success: true, id: result.insertId });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ success: false, message: 'Destinatário já cadastrado para este remetente' });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET Remetentes
app.get('/api/emails/remetentes', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT ID, EMAIL, NOME, ATIVO, CREATED_AT 
       FROM SF_EMAIL_REMETENTE 
       ORDER BY EMAIL ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET Destinatários (com JOIN remetente)
app.get('/api/emails/destinatarios', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT d.ID, d.ID_REMETENTE, d.EMAIL_DESTINATARIO, d.NOME_DESTINATARIO, d.ATIVO,
              r.EMAIL as remetenteEmail, r.NOME as remetenteNome
       FROM SF_EMAIL_DESTINATARIOS d
       JOIN SF_EMAIL_REMETENTE r ON d.ID_REMETENTE = r.ID
       ORDER BY r.EMAIL, d.EMAIL_DESTINATARIO ASC`
    );
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

function bit(v) {
  return Number(v) === 1 ? 1 : 0;
}

// LISTAR PERFIS
app.get('/api/perfis', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        id,
        nome,
        pedidos,
        pedidos_dashboard_geral,
        pedidos_dashboard_minha,
        pedidos_supervisor,
        pedidos_incluir,
        pedidos_editar,
        pedidos_excluir,
        clientes,
        clientes_incluir,
        clientes_editar,
        clientes_excluir,
        marketing,
        email_automaticos,
        agendar_sala_reuniao,
        excluir_agendamento_sala_reuniao,
        reservar_carro,
        excluir_reserva_carro,
        gestao_usuarios,
        gestao_usuarios_cadastro,
        gestao_usuarios_incluir,
        gestao_usuarios_editar,
        gestao_usuarios_excluir,
        estoque,
        estoque_almoxarifado,
        estoque_fazenda,
        estoque_cadastrar,
        estoque_transferir,
        estoque_receber,
        perfil_acesso
      FROM SF_PERFIL
      ORDER BY nome ASC
    `);

    res.json({ success: true, items: rows });
  } catch (err) {
    console.error('Erro ao listar perfis:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar perfis.',
      error: err.message
    });
  }
});

// BUSCAR PERFIL POR ID
app.get('/api/perfis/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do perfil inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        id,
        nome,
        pedidos,
        pedidos_dashboard_geral,
        pedidos_dashboard_minha,
        pedidos_supervisor,
        pedidos_incluir,
        pedidos_editar,
        pedidos_excluir,
        clientes,
        clientes_incluir,
        clientes_editar,
        clientes_excluir,
        marketing,
        email_automaticos,
        agendar_sala_reuniao,
        excluir_agendamento_sala_reuniao,
        reservar_carro,
        excluir_reserva_carro,
        gestao_usuarios,
        gestao_usuarios_cadastro,
        gestao_usuarios_incluir,
        gestao_usuarios_editar,
        gestao_usuarios_excluir,
        estoque,
        estoque_almoxarifado,
        estoque_fazenda,
        estoque_cadastrar,
        estoque_transferir,
        estoque_receber,
        perfil_acesso
      FROM SF_PERFIL
      WHERE id = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Perfil não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    console.error('Erro /api/perfis/:id GET', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar perfil.',
      error: err.message
    });
  }
});

// CRIAR PERFIL
app.post('/api/perfis', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const nome = texto(req.body?.nome);
    const usuarioId = req.body?.usuario_id ?? null;
    const usuarioNome = texto(req.body?.usuario_nome) || null;

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome do perfil é obrigatório.'
      });
    }

    await conn.beginTransaction();

    const payloadDepois = {
      nome,
      pedidos: bit(req.body?.pedidos),
      pedidos_dashboard_geral: bit(req.body?.pedidos_dashboard_geral),
      pedidos_dashboard_minha: bit(req.body?.pedidos_dashboard_minha),
      pedidos_supervisor: bit(req.body?.pedidos_supervisor),
      pedidos_incluir: bit(req.body?.pedidos_incluir),
      pedidos_editar: bit(req.body?.pedidos_editar),
      pedidos_excluir: bit(req.body?.pedidos_excluir),
      clientes: bit(req.body?.clientes),
      clientes_incluir: bit(req.body?.clientes_incluir),
      clientes_editar: bit(req.body?.clientes_editar),
      clientes_excluir: bit(req.body?.clientes_excluir),
      marketing: bit(req.body?.marketing),
      email_automaticos: bit(req.body?.email_automaticos),
      agendar_sala_reuniao: bit(req.body?.agendar_sala_reuniao),
      excluir_agendamento_sala_reuniao: bit(req.body?.excluir_agendamento_sala_reuniao),
      reservar_carro: bit(req.body?.reservar_carro),
      excluir_reserva_carro: bit(req.body?.excluir_reserva_carro),
      gestao_usuarios: bit(req.body?.gestao_usuarios),
      gestao_usuarios_cadastro: bit(req.body?.gestao_usuarios_cadastro),
      gestao_usuarios_incluir: bit(req.body?.gestao_usuarios_incluir),
      gestao_usuarios_editar: bit(req.body?.gestao_usuarios_editar),
      gestao_usuarios_excluir: bit(req.body?.gestao_usuarios_excluir),
      estoque: bit(req.body?.estoque),
      estoque_almoxarifado: bit(req.body?.estoque_almoxarifado),
      estoque_fazenda: bit(req.body?.estoque_fazenda),
      estoque_cadastrar: bit(req.body?.estoque_cadastrar),
      estoque_transferir: bit(req.body?.estoque_transferir),
      estoque_receber: bit(req.body?.estoque_receber),
      perfil_acesso: bit(req.body?.perfil_acesso)
    };

    const [result] = await conn.query(`
      INSERT INTO SF_PERFIL (
        nome,
        pedidos,
        pedidos_dashboard_geral,
        pedidos_dashboard_minha,
        pedidos_supervisor,
        pedidos_incluir,
        pedidos_editar,
        pedidos_excluir,
        clientes,
        clientes_incluir,
        clientes_editar,
        clientes_excluir,
        marketing,
        email_automaticos,
        agendar_sala_reuniao,
        excluir_agendamento_sala_reuniao,
        reservar_carro,
        excluir_reserva_carro,
        gestao_usuarios,
        gestao_usuarios_cadastro,
        gestao_usuarios_incluir,
        gestao_usuarios_editar,
        gestao_usuarios_excluir,
        estoque,
        estoque_almoxarifado,
        estoque_fazenda,
        estoque_cadastrar,
        estoque_transferir,
        estoque_receber,
        perfil_acesso
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      payloadDepois.nome,
      payloadDepois.pedidos,
      payloadDepois.pedidos_dashboard_geral,
      payloadDepois.pedidos_dashboard_minha,
      payloadDepois.pedidos_supervisor,
      payloadDepois.pedidos_incluir,
      payloadDepois.pedidos_editar,
      payloadDepois.pedidos_excluir,
      payloadDepois.clientes,
      payloadDepois.clientes_incluir,
      payloadDepois.clientes_editar,
      payloadDepois.clientes_excluir,
      payloadDepois.marketing,
      payloadDepois.email_automaticos,
      payloadDepois.agendar_sala_reuniao,
      payloadDepois.excluir_agendamento_sala_reuniao,
      payloadDepois.reservar_carro,
      payloadDepois.excluir_reserva_carro,
      payloadDepois.gestao_usuarios,
      payloadDepois.gestao_usuarios_cadastro,
      payloadDepois.gestao_usuarios_incluir,
      payloadDepois.gestao_usuarios_editar,
      payloadDepois.gestao_usuarios_excluir,
      payloadDepois.estoque,
      payloadDepois.estoque_almoxarifado,
      payloadDepois.estoque_fazenda,
      payloadDepois.estoque_cadastrar,
      payloadDepois.estoque_transferir,
      payloadDepois.estoque_receber,
      payloadDepois.perfil_acesso
    ]);

    const idPerfil = Number(result?.insertId || 0);

    if (!idPerfil) {
      throw new Error('Não foi possível obter o ID do perfil criado.');
    }

    await conn.query(`
      INSERT INTO SF_PERFIL_LOG (
        id_perfil,
        acao,
        usuario_id,
        usuario_nome,
        detalhes
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      idPerfil,
      'CRIACAO',
      usuarioId,
      usuarioNome,
      JSON.stringify({
        depois: payloadDepois
      })
    ]);

    await conn.commit();

    return res.status(201).json({
      success: true,
      item: {
        id: idPerfil,
        ...payloadDepois
      },
      message: 'Perfil criado com sucesso.'
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/perfis POST', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao criar perfil.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

// EDITAR PERFIL
app.put('/api/perfis/:id', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const id = Number(req.params.id);
    const nome = texto(req.body?.nome);
    const usuarioId = req.body?.usuario_id ?? null;
    const usuarioNome = texto(req.body?.usuario_nome) || null;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do perfil inválido.'
      });
    }

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome do perfil é obrigatório.'
      });
    }

    await conn.beginTransaction();

    const [atualRows] = await conn.query(`
      SELECT * FROM SF_PERFIL WHERE id = ? LIMIT 1
    `, [id]);

    if (!atualRows.length) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Perfil não encontrado.'
      });
    }

    const antes = atualRows[0];

    const depois = {
      nome,
      pedidos: bit(req.body?.pedidos),
      pedidos_dashboard_geral: bit(req.body?.pedidos_dashboard_geral),
      pedidos_dashboard_minha: bit(req.body?.pedidos_dashboard_minha),
      pedidos_supervisor: bit(req.body?.pedidos_supervisor),
      pedidos_incluir: bit(req.body?.pedidos_incluir),
      pedidos_editar: bit(req.body?.pedidos_editar),
      pedidos_excluir: bit(req.body?.pedidos_excluir),
      clientes: bit(req.body?.clientes),
      clientes_incluir: bit(req.body?.clientes_incluir),
      clientes_editar: bit(req.body?.clientes_editar),
      clientes_excluir: bit(req.body?.clientes_excluir),
      marketing: bit(req.body?.marketing),
      email_automaticos: bit(req.body?.email_automaticos),
      agendar_sala_reuniao: bit(req.body?.agendar_sala_reuniao),
      excluir_agendamento_sala_reuniao: bit(req.body?.excluir_agendamento_sala_reuniao),
      reservar_carro: bit(req.body?.reservar_carro),
      excluir_reserva_carro: bit(req.body?.excluir_reserva_carro),
      gestao_usuarios: bit(req.body?.gestao_usuarios),
      gestao_usuarios_cadastro: bit(req.body?.gestao_usuarios_cadastro),
      gestao_usuarios_incluir: bit(req.body?.gestao_usuarios_incluir),
      gestao_usuarios_editar: bit(req.body?.gestao_usuarios_editar),
      gestao_usuarios_excluir: bit(req.body?.gestao_usuarios_excluir),
      estoque: bit(req.body?.estoque),
      estoque_almoxarifado: bit(req.body?.estoque_almoxarifado),
      estoque_fazenda: bit(req.body?.estoque_fazenda),
      estoque_cadastrar: bit(req.body?.estoque_cadastrar),
      estoque_transferir: bit(req.body?.estoque_transferir),
      estoque_receber: bit(req.body?.estoque_receber),
      perfil_acesso: bit(req.body?.perfil_acesso)
    };

    const [result] = await conn.query(`
      UPDATE SF_PERFIL SET
        nome = ?,
        pedidos = ?,
        pedidos_dashboard_geral = ?,
        pedidos_dashboard_minha = ?,
        pedidos_supervisor = ?,
        pedidos_incluir = ?,
        pedidos_editar = ?,
        pedidos_excluir = ?,
        clientes = ?,
        clientes_incluir = ?,
        clientes_editar = ?,
        clientes_excluir = ?,
        marketing = ?,
        email_automaticos = ?,
        agendar_sala_reuniao = ?,
        excluir_agendamento_sala_reuniao = ?,
        reservar_carro = ?,
        excluir_reserva_carro = ?,
        gestao_usuarios = ?,
        gestao_usuarios_cadastro = ?,
        gestao_usuarios_incluir = ?,
        gestao_usuarios_editar = ?,
        gestao_usuarios_excluir = ?,
        estoque = ?,
        estoque_almoxarifado = ?,
        estoque_fazenda = ?,
        estoque_cadastrar = ?,
        estoque_transferir = ?,
        estoque_receber = ?,
        perfil_acesso = ?
      WHERE id = ?
    `, [
      depois.nome,
      depois.pedidos,
      depois.pedidos_dashboard_geral,
      depois.pedidos_dashboard_minha,
      depois.pedidos_supervisor,
      depois.pedidos_incluir,
      depois.pedidos_editar,
      depois.pedidos_excluir,
      depois.clientes,
      depois.clientes_incluir,
      depois.clientes_editar,
      depois.clientes_excluir,
      depois.marketing,
      depois.email_automaticos,
      depois.agendar_sala_reuniao,
      depois.excluir_agendamento_sala_reuniao,
      depois.reservar_carro,
      depois.excluir_reserva_carro,
      depois.gestao_usuarios,
      depois.gestao_usuarios_cadastro,
      depois.gestao_usuarios_incluir,
      depois.gestao_usuarios_editar,
      depois.gestao_usuarios_excluir,
      depois.estoque,
      depois.estoque_almoxarifado,
      depois.estoque_fazenda,
      depois.estoque_cadastrar,
      depois.estoque_transferir,
      depois.estoque_receber,
      depois.perfil_acesso,
      id
    ]);

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Perfil não encontrado para atualização.'
      });
    }

    await conn.query(`
      INSERT INTO SF_PERFIL_LOG (
        id_perfil,
        acao,
        usuario_id,
        usuario_nome,
        detalhes
      ) VALUES (?, ?, ?, ?, ?)
    `, [
      id,
      'ALTERACAO',
      usuarioId,
      usuarioNome,
      JSON.stringify({ antes, depois })
    ]);

    await conn.commit();

    return res.json({
      success: true,
      item: {
        id,
        ...depois
      },
      message: 'Perfil atualizado com sucesso.'
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/perfis/:id PUT', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar perfil.',
      error: err.message
    });
  } finally {
    conn.release();
  }
});

// LISTAR LOGS DO PERFIL
app.get('/api/perfis/:id/logs', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do perfil inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        id,
        id_perfil,
        acao,
        usuario_id,
        usuario_nome,
        data_hora,
        detalhes
      FROM SF_PERFIL_LOG
      WHERE id_perfil = ?
      ORDER BY data_hora DESC, id DESC
    `, [id]);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro /api/perfis/:id/logs GET', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar logs do perfil.',
      error: err.message
    });
  }
});


// permissões
app.get('/api/permissoes/agendar-sala/:usuarioId', async (req, res) => {
  try {
    const usuarioId = Number(req.params.usuarioId);

    if (!usuarioId) {
      return res.status(400).json({
        success: false,
        message: 'ID do usuário inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        u.ID AS usuario_id,
        u.NOME AS usuario_nome,
        u.PERFIL AS perfil,
        p.agendar_sala_reuniao
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON p.nome = u.perfil
      WHERE u.ID = ?
      LIMIT 1
    `, [usuarioId]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const item = rows[0];
    const permitido = Number(item.agendar_sala_reuniao) === 1;

    return res.json({
      success: true,
      permitido,
      item: {
        usuario_id: item.usuario_id,
        usuario_nome: item.usuario_nome,
        perfil: item.perfil,
        agendar_sala_reuniao: permitido ? 1 : 0
      }
    });
  } catch (err) {
    console.error('Erro ao validar permissão de agendar sala:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao validar permissão.',
      error: err.message
    });
  }
});

// permissão menu lateral
app.get('/api/permissoes/menu/:usuarioId', async (req, res) => {
  try {
    const usuarioId = Number(req.params.usuarioId);

    if (!usuarioId) {
      return res.status(400).json({
        success: false,
        message: 'ID do usuário inválido.'
      });
    }

    const rows = await pool.query(`
      SELECT
        u.ID AS usuario_id,
        u.NOME AS usuario_nome,
        u.PERFIL AS perfil,
        COALESCE(p.pedidos, 0) AS pedidos,
        COALESCE(p.clientes, 0) AS clientes,
        COALESCE(p.marketing, 0) AS marketing,
        COALESCE(p.email_automaticos, 0) AS email_automaticos,
        COALESCE(p.gestao_usuarios, 0) AS gestao_usuarios,
        COALESCE(p.estoque, 0) AS estoque,
        COALESCE(p.perfil_acesso, 0) AS perfil_acesso
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p ON p.nome = u.perfil
      WHERE u.ID = ?
      LIMIT 1
    `, [usuarioId]);


    if (!rows || !rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const item = rows[0][0];


    const payload = {
      success: true,
      item: {
        usuario_id: Number(item.usuario_id) || 0,
        usuario_nome: item.usuario_nome || '',
        perfil: item.perfil || '',
        pedidos: Number(item.pedidos ?? 0),
        clientes: Number(item.clientes ?? 0),
        marketing: Number(item.marketing ?? 0),
        emailautomaticos: Number(item.email_automaticos ?? 0),
        gestaousuarios: Number(item.gestao_usuarios ?? 0),
        estoque: Number(item.estoque ?? 0),
        perfilacesso: Number(item.perfil_acesso ?? 0)
      }
    };


    return res.json(payload);
  } catch (err) {
    console.error('[API /permissoes/menu] erro:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao validar permissões do menu.',
      error: err.message
    });
  }
});

app.get('/api/permissoes/estoque-almoxarifado/:usuarioId', async (req, res) => {
  try {
    const usuarioId = Number(req.params.usuarioId);

    if (!usuarioId) {
      return res.status(400).json({
        success: false,
        message: 'ID do usuário inválido.'
      });
    }

    const [rows] = await pool.query(
      `
      SELECT
        u.ID AS usuario_id,
        u.NOME AS usuario_nome,
        u.PERFIL AS perfil,
        p.estoque_almoxarifado
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON p.nome = u.perfil
      WHERE u.ID = ?
      LIMIT 1
      `,
      [usuarioId]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const item = rows[0];
    const permitido = Number(item.estoque_almoxarifado) === 1;

    return res.json({
      success: true,
      permitido,
      item: {
        usuario_id: item.usuario_id,
        usuario_nome: item.usuario_nome,
        perfil: item.perfil,
        estoque_almoxarifado: permitido ? 1 : 0
      }
    });
  } catch (err) {
    console.error('Erro ao validar permissão do almoxarifado:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao validar permissão.',
      error: err.message
    });
  }
});

app.get('/api/estoque/produto/:idProduto/saldo/:idLocalAlmoxarifado', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.params.idProduto);
    const idLocalAlmoxarifado = Number(req.params.idLocalAlmoxarifado);

    if (!idProduto || !idLocalAlmoxarifado) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalAlmoxarifado.'
      });
    }

    conn = await pool.getConnection();

    const produto = await validarProdutoSistema(conn, idProduto);
    if (!produto) {
      return res.status(404).json({
        success: false,
        message: 'Produto não encontrado na SF_PRODUTOS.'
      });
    }

    // QUERY 1: Entradas DESSE local
    const [rowsEntrada] = await conn.query(`
      SELECT SUM(COALESCE(pe.qtd_nf, 0)) AS qtd_entrada
      FROM SF_PRODUTO_ENTRADA pe
      WHERE pe.produto_sistema_id = ?
        AND pe.ID_LOCAL_ALMOXARIFADO = ?
        AND pe.produto_sistema_id IS NOT NULL
        AND pe.ID_LOCAL_ALMOXARIFADO IS NOT NULL
    `, [idProduto, idLocalAlmoxarifado]);

    // QUERY 2: Transferências DESSE local
    const [rowsTransferencia] = await conn.query(`
      SELECT SUM(COALESCE(t.QUANTIDADE, 0)) AS qtd_transferida
      FROM SF_ESTOQUE_TRANSFERENCIA t
      WHERE t.ID_PRODUTO = ?
        AND t.ID_LOCAL_ORIGEM = ?
        AND t.ID_PRODUTO IS NOT NULL
        AND UPPER(TRIM(COALESCE(t.STATUS_TRANSFERENCIA, ''))) NOT IN ('EXCLUIDA', 'RECUSADA')
    `, [idProduto, idLocalAlmoxarifado]);

    const qtdEntrada = Number(rowsEntrada?.[0]?.qtd_entrada ?? 0);
    const qtdTransferida = Number(rowsTransferencia?.[0]?.qtd_transferida ?? 0);
    const saldo = qtdEntrada - qtdTransferida < 0 ? 0 : qtdEntrada - qtdTransferida;

    return res.json({
      success: true,
      produto,
      localAlmoxarifado: idLocalAlmoxarifado,
      qtdEntrada,
      qtdTransferida,
      saldo
    });

  } catch (err) {
    console.error('Erro ao calcular saldo do produto:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao calcular saldo do produto.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// GET api/clima-links
app.get('/api/clima-links', async (req, res) => {
  try {
    const rows = await pool.query(`
      SELECT id, titulo, url, icone 
      FROM SF_CLIMA_LINKS 
    `);
    res.json({ success: true, items: rows });
  } catch (err) {
    console.error('Erro api/clima-links:', err);
    res.status(500).json({ success: false, message: 'Erro ao listar links de clima.', error: err.message });
  }
});

// RESERVAR CARRO

app.get('/api/local-trabalho', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        id,
        nome
      FROM SF_LOCAL_TRABALHO
      ORDER BY nome
    `);

    return res.json({
      success: true,
      items: rows
    });

  } catch (err) {
    console.error('Erro ao listar locais de trabalho:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar locais de trabalho.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro', async (req, res) => {
  let conn;

  try {
    const {
      tipoVeiculo,
      dataNecessaria,
      previsaoDevolucao,
      destinos,
      observacoes,
      urgencia,
      usuarioSolicitante
    } = req.body || {};

    if (!tipoVeiculo || !dataNecessaria || !previsaoDevolucao || !urgencia || !usuarioSolicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipoVeiculo, dataNecessaria, previsaoDevolucao, urgencia e usuarioSolicitante.'
      });
    }

    if (!Array.isArray(destinos) || !destinos.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    if (new Date(previsaoDevolucao) <= new Date(dataNecessaria)) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [insertReserva] = await conn.query(`
      INSERT INTO SF_RESERVA_CARRO (
        tipo_veiculo,
        data_necessaria,
        previsao_devolucao,
        urgencia,
        observacoes,
        usuario_solicitante
      ) VALUES (?, ?, ?, ?, ?, ?)
    `, [
      String(tipoVeiculo).trim().toUpperCase(),
      dataNecessaria,
      previsaoDevolucao,
      String(urgencia).trim().toUpperCase(),
      observacoes ? String(observacoes).trim() : null,
      String(usuarioSolicitante).trim()
    ]);

    const reservaId = Number(insertReserva.insertId);

    for (const idDestinoRaw of destinos) {
      const idDestino = Number(idDestinoRaw);

      if (!idDestino) {
        throw new Error('Foi encontrado um destino inválido na solicitação.');
      }

      await conn.query(`
        INSERT INTO SF_RESERVA_CARRO_DESTINO (
          reserva_id,
          local_trabalho_id
        ) VALUES (?, ?)
      `, [reservaId, idDestino]);
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Solicitação de reserva de carro salva com sucesso.',
      reservaId
    });

  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao salvar reserva de carro:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar reserva de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/reservas-carro', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao,
        GROUP_CONCAT(lt.nome ORDER BY lt.nome SEPARATOR ' | ') AS destinos
      FROM SF_RESERVA_CARRO rc
      LEFT JOIN SF_RESERVA_CARRO_DESTINO rcd
        ON rcd.reserva_id = rc.id
      LEFT JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id
      GROUP BY
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao
      ORDER BY rc.id DESC
    `);

    return res.json({
      success: true,
      items: rows
    });

  } catch (err) {
    console.error('Erro ao listar reservas de carro:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar reservas de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/reservas-carro/:id', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    conn = await pool.getConnection();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        tipo_veiculo,
        data_necessaria,
        previsao_devolucao,
        urgencia,
        observacoes,
        usuario_solicitante,
        data_solicitacao,
        status_solicitacao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];
    if (!reserva) {
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    const [rowsDestinos] = await conn.query(`
      SELECT
        lt.id,
        lt.nome
      FROM SF_RESERVA_CARRO_DESTINO rcd
      INNER JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id
      WHERE rcd.reserva_id = ?
      ORDER BY lt.nome
    `, [idReserva]);

    return res.json({
      success: true,
      item: {
        ...reserva,
        destinos: rowsDestinos
      }
    });

  } catch (err) {
    console.error('Erro ao buscar reserva de carro:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar reserva de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/reservas-carro/:id/status', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const status = String(req.body?.status || '').trim().toUpperCase();

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    const statusPermitidos = ['PENDENTE', 'APROVADA', 'RECUSADA', 'CANCELADA', 'CONCLUIDA'];
    if (!statusPermitidos.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Status inválido.'
      });
    }

    conn = await pool.getConnection();

    const [result] = await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET status_solicitacao = ?
      WHERE id = ?
    `, [status, idReserva]);

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    return res.json({
      success: true,
      message: 'Status da reserva atualizado com sucesso.'
    });

  } catch (err) {
    console.error('Erro ao atualizar status da reserva:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar status da reserva.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/clima-links', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT id, titulo, url, icone
      FROM SF_CLIMA_LINKS
      ORDER BY id
    `);

    return res.json({
      success: true,
      items: rows
    });

  } catch (err) {
    console.error('Erro api/clima-links:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar links de clima.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/reservas-carro/usuario/:usuarioSolicitante', async (req, res) => {
  let conn;

  try {
    const usuarioSolicitante = String(req.params.usuarioSolicitante || '').trim();

    if (!usuarioSolicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário solicitante.'
      });
    }

    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao,
        GROUP_CONCAT(lt.nome ORDER BY lt.nome SEPARATOR ' | ') AS destinos
      FROM SF_RESERVA_CARRO rc
      LEFT JOIN SF_RESERVA_CARRO_DESTINO rcd
        ON rcd.reserva_id = rc.id
      LEFT JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id
      WHERE UPPER(TRIM(rc.usuario_solicitante)) = UPPER(TRIM(?))
      GROUP BY
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao
      ORDER BY rc.id DESC
    `, [usuarioSolicitante]);

    return res.json({
      success: true,
      items: rows
    });

  } catch (err) {
    console.error('Erro ao listar agendamentos do usuário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar agendamentos do usuário.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});




// =====================
// Inicia servidor (sempre por último)
// =====================
app.listen(PORT, () => {
  console.log(`🚀 API rodando na porta ${PORT}`);
  console.log('✅ Teste: /health');
});

