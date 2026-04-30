import express from 'express';
import cors from 'cors';
import { pool } from './db.js';
import dotenv from 'dotenv';
import dns from 'node:dns';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import multer from 'multer';
import fetch from 'node-fetch';
import cron from 'node-cron';
import XLSX from 'xlsx';
import puppeteer from 'puppeteer';
import ping from 'ping';
import { DistribuicaoDFe } from 'node-mde';
import AdmZip from 'adm-zip';
import zlib from 'node:zlib';
import https from 'node:https';
import http from 'node:http';



import { titleCaseNome, normalizarEmail, somenteNumeros } from './utils.js';



function getEnv(name, required = true) {
  const value = String(process.env[name] || '').trim();

  if (required && !value) {
    throw new Error(`Variável de ambiente obrigatória não configurada: ${name}`);
  }

  return value;
}

function getZApiConfig() {
  const baseUrl = getEnv('ZAPI_BASE_URL');
  const instanceId = getEnv('ZAPI_INSTANCE_ID');
  const instanceToken = getEnv('ZAPI_INSTANCE_TOKEN');
  const clientToken = String(process.env.ZAPI_CLIENT_TOKEN || '').trim();

  return {
    baseUrl,
    instanceId,
    instanceToken,
    clientToken
  };
}

function getZApiSendTextUrl() {
  const { baseUrl, instanceId, instanceToken } = getZApiConfig();
  return `${baseUrl}/instances/${instanceId}/token/${instanceToken}/send-text`;
}

function getZApiSendImageUrl() {
  const { baseUrl, instanceId, instanceToken } = getZApiConfig();
  return `${baseUrl}/instances/${instanceId}/token/${instanceToken}/send-image`;
}

function getZApiStatusUrl() {
  const { baseUrl, instanceId, instanceToken } = getZApiConfig();
  return `${baseUrl}/instances/${instanceId}/token/${instanceToken}/status`;
}

dns.setDefaultResultOrder("ipv4first");
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const uploadMemoria = multer({ storage: multer.memoryStorage() });

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


    const rows = Array.isArray(result?.[0]) ? result[0] : result;


    const hoje = new Date();
    const diaHoje = hoje.getDate();
    const mesHoje = hoje.getMonth() + 1;


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

      return item;
    });

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

async function listarAniversariantesHoje(conn) {
  const [rows] = await conn.query(`
    SELECT
      ID,
      NOME,
      SETOR,
      LOCAL_TRABALHO,
      FOTO,
      DATA_NASCIMENTO,
      TELEFONE,
      TELEFONE_PESSOAL
    FROM SF_USUARIO
    WHERE STATUS = 'Ativo'
      AND DATA_NASCIMENTO IS NOT NULL
      AND DAY(DATA_NASCIMENTO) = DAY(CURDATE())
      AND MONTH(DATA_NASCIMENTO) = MONTH(CURDATE())
    ORDER BY NOME ASC
  `);

  return rows;
}

function obterTelefonesUsuario(usuario) {
  const telefones = [
    normalizarNumeroWhatsAppBR(usuario.TELEFONE_PESSOAL),
    normalizarNumeroWhatsAppBR(usuario.TELEFONE)
  ].filter(Boolean);

  return [...new Set(telefones)];
}

function montarHtmlCardAniversario(usuario) {
  const nome = usuario?.NOME || 'Colaborador(a)';
  const setor = usuario?.SETOR || 'Setor não informado';
  const local = usuario?.LOCAL_TRABALHO || 'Local não informado';

  const logoSementes = 'https://sf-link-copy.up.railway.app/anexos/marketing/Logo%20Sementes-1775074662246-36db3a313b0ed.png';
  const logoSociedade = 'https://sf-link-copy.up.railway.app/anexos/marketing/Logo%20Sociedade-1774616271956-ca397ee063a7b.png';

  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <title>Feliz Aniversário</title>
      <style>
        * { box-sizing: border-box; }

        body {
          margin: 0;
          font-family: Arial, Helvetica, sans-serif;
          background: #ffffff;
        }

        .canvas {
          width: 1080px;
          height: 1350px;
          padding: 40px;
          background:
            radial-gradient(circle at top left, rgba(11, 31, 58, 0.05), transparent 28%),
            radial-gradient(circle at bottom right, rgba(22, 163, 74, 0.08), transparent 28%),
            linear-gradient(180deg, #ffffff 0%, #f7fbff 55%, #f4fbf6 100%);
        }

        .card {
          width: 100%;
          height: 100%;
          border-radius: 34px;
          overflow: hidden;
          background: linear-gradient(180deg, #ffffff 0%, #f8fbff 65%, #f5fbf7 100%);
          box-shadow: 0 24px 70px rgba(11, 31, 58, 0.10);
          border: 1px solid #e5edf5;
          display: flex;
          flex-direction: column;
          position: relative;
        }

        .balloon {
          position: absolute;
          border-radius: 50%;
          z-index: 0;
          opacity: 0.9;
        }

        .balloon::after {
          content: '';
          position: absolute;
          width: 2px;
          height: 95px;
          background: rgba(148, 163, 184, 0.45);
          left: 50%;
          top: calc(100% - 4px);
          transform: translateX(-50%);
        }

        .balloon-1 {
          width: 130px;
          height: 155px;
          top: 95px;
          left: 38px;
          background: radial-gradient(circle at 30% 30%, #dbeafe 0%, #93c5fd 45%, #2563eb 100%);
          box-shadow: inset -12px -16px 24px rgba(11, 31, 58, 0.12);
        }

        .balloon-2 {
          width: 110px;
          height: 135px;
          top: 210px;
          right: 58px;
          background: radial-gradient(circle at 30% 30%, #dcfce7 0%, #86efac 45%, #16a34a 100%);
          box-shadow: inset -12px -16px 24px rgba(20, 83, 45, 0.12);
        }

        .balloon-3 {
          width: 88px;
          height: 108px;
          bottom: 220px;
          left: 78px;
          background: radial-gradient(circle at 30% 30%, #e0f2fe 0%, #7dd3fc 45%, #0284c7 100%);
          box-shadow: inset -10px -14px 18px rgba(8, 47, 73, 0.12);
        }

        .balloon-4 {
          width: 95px;
          height: 118px;
          bottom: 260px;
          right: 110px;
          background: radial-gradient(circle at 30% 30%, #dcfce7 0%, #4ade80 48%, #15803d 100%);
          box-shadow: inset -10px -14px 18px rgba(20, 83, 45, 0.12);
        }

        .balloon-5 {
          width: 58px;
          height: 72px;
          top: 360px;
          right: 180px;
          background: radial-gradient(circle at 30% 30%, #eff6ff 0%, #bfdbfe 50%, #3b82f6 100%);
          box-shadow: inset -8px -10px 14px rgba(30, 64, 175, 0.10);
        }

        .content-wrap {
          position: relative;
          z-index: 1;
          width: 100%;
          height: 100%;
          display: flex;
          flex-direction: column;
        }

        .header {
          padding: 54px 56px 26px;
          background: transparent;
          color: #0b1f3a;
          text-align: center;
        }

        .tag {
          display: inline-block;
          padding: 10px 22px;
          border-radius: 999px;
          background: #eaf3ff;
          border: 1px solid #d7e6f7;
          color: #0f5132;
          font-size: 22px;
          font-weight: 800;
          letter-spacing: 1px;
          margin-bottom: 22px;
          text-transform: uppercase;
        }

        .titulo {
          margin: 0;
          font-size: 66px;
          line-height: 1.06;
          font-weight: 800;
          letter-spacing: -1px;
          color: #0b1f3a;
        }

        .subtitulo {
          margin: 18px 0 0;
          font-size: 28px;
          line-height: 1.5;
          color: #334155;
        }

        .content {
          flex: 1;
          padding: 20px 56px 30px;
          display: flex;
          flex-direction: column;
          justify-content: center;
          gap: 24px;
        }

        .nome-box {
          background: linear-gradient(135deg, #eff6ff 0%, #ecfdf5 100%);
          border: 1px solid #d9e8f4;
          border-radius: 28px;
          padding: 30px 32px;
          text-align: center;
          backdrop-filter: blur(1px);
        }

        .nome-label {
          font-size: 20px;
          color: #64748b;
          font-weight: 700;
          text-transform: uppercase;
          letter-spacing: .8px;
          margin-bottom: 12px;
        }

        .nome {
          font-size: 54px;
          line-height: 1.15;
          color: #0b1f3a;
          font-weight: 800;
          word-break: break-word;
        }

        .mensagem {
          background: rgba(255, 255, 255, 0.92);
          border: 1px solid #dce7f1;
          border-radius: 24px;
          padding: 28px 30px;
          font-size: 30px;
          line-height: 1.6;
          color: #1f2937;
          font-weight: 500;
          box-shadow: 0 10px 30px rgba(11, 31, 58, 0.04);
        }

        .mensagem strong {
          color: #0b1f3a;
        }

        .grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 18px;
        }

        .info {
          background: rgba(255, 255, 255, 0.96);
          border: 1px solid #dce7f1;
          border-radius: 22px;
          padding: 22px 24px;
        }

        .label {
          font-size: 17px;
          text-transform: uppercase;
          letter-spacing: .8px;
          color: #6b7280;
          font-weight: 800;
          margin-bottom: 10px;
        }

        .valor {
          font-size: 29px;
          line-height: 1.35;
          color: #0f172a;
          font-weight: 700;
          word-break: break-word;
        }

        .footer {
          margin-top: auto;
          padding: 24px 56px 34px;
          border-top: 1px solid #e5edf5;
          background: transparent;
        }

        .footer-texto {
          text-align: center;
          font-size: 23px;
          line-height: 1.6;
          color: #166534;
          font-weight: 600;
          margin-bottom: 24px;
        }

        .footer-texto strong {
          color: #0b1f3a;
        }

        .logos-footer {
          display: flex;
          justify-content: center;
          align-items: stretch;
          gap: 18px;
        }

        .logo-slot {
          width: 320px;
          height: 110px;
          border-radius: 22px;
          border: 1px solid #dbe7f1;
          background: rgba(255, 255, 255, 0.96);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 14px 18px;
        }

        .logo-slot img {
          display: block;
          width: auto;
          height: auto;
          object-fit: contain;
          max-width: 100%;
        }

        .logo-slot.logo-esquerda img {
          max-width: 240px;
          max-height: 52px;
        }

        .logo-slot.logo-direita img {
          max-width: 300px;
          max-height: 85px;
        }
      </style>
    </head>
    <body>
      <div class="canvas">
        <div class="card">
          <div class="balloon balloon-1"></div>
          <div class="balloon balloon-2"></div>
          <div class="balloon balloon-3"></div>
          <div class="balloon balloon-4"></div>
          <div class="balloon balloon-5"></div>

          <div class="content-wrap">
            <div class="header">
              <div class="tag">Mensagem Especial</div>
              <h1 class="titulo">Feliz Aniversário!</h1>
              <p class="subtitulo">
                Hoje celebramos uma data especial com reconhecimento, carinho e gratidão.
              </p>
            </div>

            <div class="content">
              <div class="nome-box">
                <div class="nome-label">Homenagem para</div>
                <div class="nome">${escapeHtml(nome)}</div>
              </div>

              <div class="mensagem">
                A <strong>Sociedade Franciosi</strong> cumprimenta você pelo seu aniversário e deseja
                um novo ciclo de muita <strong>saúde</strong>, <strong>paz</strong>,
                <strong>prosperidade</strong> e <strong>realizações</strong>.
                Receba nossa consideração e os votos de um dia muito especial.
              </div>

              <div class="grid">
                <div class="info">
                  <div class="label">Setor</div>
                  <div class="valor">${escapeHtml(setor)}</div>
                </div>

                <div class="info">
                  <div class="label">Local de trabalho</div>
                  <div class="valor">${escapeHtml(local)}</div>
                </div>
              </div>
            </div>

            <div class="footer">
              <div class="footer-texto">
                Com estima e reconhecimento,<br />
                <strong>Sociedade Franciosi</strong>
              </div>

              <div class="logos-footer">
                <div class="logo-slot logo-esquerda">
                  <img
                    src="${logoSementes}"
                    alt="Logo Sementes"
                    width="240"
                    height="52"
                  />
                </div>

                <div class="logo-slot logo-direita">
                  <img
                    src="${logoSociedade}"
                    alt="Logo Sociedade Franciosi"
                    width="255"
                    height="60"
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </body>
  </html>
  `;
}

async function gerarImagemAniversarioBase64(usuario) {
  const html = montarHtmlCardAniversario(usuario);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1080, height: 1350, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: 'networkidle0' });

    const buffer = await page.screenshot({
      type: 'png'
    });

    return `data:image/png;base64,${buffer.toString('base64')}`;
  } finally {
    await browser.close();
  }
}

async function enviarParabensParaUsuario(usuario) {
  const telefones = obterTelefonesUsuario(usuario);

  if (!telefones.length) {
    return {
      usuarioId: usuario.ID,
      nome: usuario.NOME,
      sucesso: false,
      erro: 'Usuário sem telefone válido'
    };
  }

  const imageBase64 = await gerarImagemAniversarioBase64(usuario);
  const caption = `🎉 Feliz aniversário, ${usuario.NOME || 'colaborador(a)'}! Desejamos um dia especial e muitas felicidades.`;

  const envios = [];

  for (const telefone of telefones) {
    try {
      const retorno = await enviarImagemWhatsAppZApi({
        telefone,
        imageBase64,
        caption
      });

      envios.push({
        telefone,
        sucesso: true,
        retorno
      });
    } catch (err) {
      envios.push({
        telefone,
        sucesso: false,
        erro: err.message
      });
    }
  }

  return {
    usuarioId: usuario.ID,
    nome: usuario.NOME,
    sucesso: envios.some(item => item.sucesso),
    envios
  };
}

async function jaEnviadoAniversarioHoje(conn, usuarioId) {
  const [rows] = await conn.query(
    `
    SELECT ID
    FROM SF_LOG_ANIVERSARIO_WHATSAPP
    WHERE USUARIO_ID = ?
      AND DATA_ENVIO = CURDATE()
    LIMIT 1
    `,
    [usuarioId]
  );

  return rows.length > 0;
}

async function registrarEnvioAniversario(conn, usuarioId, telefones, statusEnvio, observacao = null) {
  await conn.query(
    `
    INSERT INTO SF_LOG_ANIVERSARIO_WHATSAPP
      (USUARIO_ID, DATA_ENVIO, TELEFONES, STATUS_ENVIO, OBSERVACAO)
    VALUES
      (?, CURDATE(), ?, ?, ?)
    `,
    [
      usuarioId,
      Array.isArray(telefones) ? telefones.join(', ') : String(telefones || ''),
      statusEnvio,
      observacao
    ]
  );
}

async function executarRotinaAniversariantes() {
  let conn;

  try {
    conn = await pool.getConnection();

    const aniversariantes = await listarAniversariantesHoje(conn);

    if (!aniversariantes.length) {
      console.log('[ANIVERSARIANTES] Nenhum aniversariante hoje.');
      return;
    }

    for (const usuario of aniversariantes) {
      try {
        const jaEnviado = await jaEnviadoAniversarioHoje(conn, usuario.ID);

        if (jaEnviado) {
          console.log(`[ANIVERSARIANTES] Já enviado hoje para ${usuario.NOME}.`);
          continue;
        }

        const resultado = await enviarParabensParaUsuario(usuario);
        const telefones = obterTelefonesUsuario(usuario);

        await registrarEnvioAniversario(
          conn,
          usuario.ID,
          telefones,
          resultado.sucesso ? 'ENVIADO' : 'ERRO',
          resultado.sucesso ? null : (resultado?.envios?.map(e => `${e.telefone}: ${e.erro || 'falha'}`).join(' | ') || 'Falha no envio')
        );

        console.log('[ANIVERSARIANTES] Resultado:', resultado);
      } catch (errUsuario) {
        console.error(`[ANIVERSARIANTES] Erro ao processar ${usuario.NOME}:`, errUsuario.message);

        try {
          await registrarEnvioAniversario(
            conn,
            usuario.ID,
            obterTelefonesUsuario(usuario),
            'ERRO',
            errUsuario.message
          );
        } catch {}
      }
    }
  } catch (err) {
    console.error('[ANIVERSARIANTES] Erro na rotina automática:', err);
  } finally {
    if (conn) conn.release();
  }
}

cron.schedule('0 8,14 * * *', async () => {
  console.log('[CRON] Iniciando verificação de aniversariantes...');
  await executarRotinaAniversariantes();
}, {
  timezone: 'America/Bahia'
});

app.post('/api/aniversariantes/enviar-hoje', async (req, res) => {
  try {
    await executarRotinaAniversariantes();

    return res.json({
      success: true,
      message: 'Rotina de aniversariantes executada com sucesso.'
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao executar rotina de aniversariantes.',
      error: err.message
    });
  }
});

app.get('/api/aniversariantes/testar-hoje', async (req, res) => {
  try {
    const resultado = await executarRotinaAniversariantes();

    return res.json({
      success: true,
      message: 'Rotina de aniversariantes executada com sucesso.',
      resultado
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao executar rotina de aniversariantes.',
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
      `SELECT id, nome, email, setor, telefone
         FROM SF_USUARIO
        WHERE email IS NOT NULL AND email <> ''
        AND status <> 'Desativado'
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

app.post('/api/gestao-usuarios-adicionar', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome);
    const email = normalizarEmail(req.body?.email);
    const senha = texto(req.body?.senha);
    const telefone = somenteNumeros(req.body?.telefone);
    const perfil = texto(req.body?.perfil);
    const setor = titleCaseNome(req.body?.setor);

    const funcao = texto(req.body?.funcao);
    const data_admissao = nullableDate(req.body?.dataadmissao || req.body?.data_admissao);

    const centro_custo = titleCaseNome(req.body?.localtrabalho || req.body?.local_trabalho || req.body?.centro_custo);
    const local_trabalho = titleCaseNome(req.body?.unidadetrabalho || req.body?.unidade_trabalho || req.body?.local_trabalho);

    const status = texto(req.body?.status) || 'Ativo';

    const cpf = somenteNumeros(req.body?.cpf);
    const rg = texto(req.body?.rg);
    const cnh = texto(req.body?.cnh);

    const cnhCategoriaBruta = texto(req.body?.cnh_categoria || req.body?.cnhcategoria);
    const cnh_categoria = cnhCategoriaBruta ? cnhCategoriaBruta.toUpperCase() : null;

    const cnh_validade = nullableDate(req.body?.cnh_validade || req.body?.cnhvalidade);
    const cnh_arquivo = texto(req.body?.cnh_arquivo || req.body?.cnharquivo);
    const data_nascimento = nullableDate(req.body?.data_nascimento || req.body?.datanascimento);
    const estado_civil = texto(req.body?.estado_civil || req.body?.estadocivil);
    const telefone_pessoal = somenteNumeros(req.body?.telefone_pessoal || req.body?.telefonepessoal);

    const emailPessoalBruto = texto(req.body?.email_pessoal || req.body?.emailpessoal);
    const email_pessoal = emailPessoalBruto ? normalizarEmail(emailPessoalBruto) : null;

    const foto = texto(req.body?.foto);

    const apelido = texto(req.body?.apelido);
    const numero_calcado = String(req.body?.numerocalcado ?? '').trim() !== ''
      ? Number(req.body?.numerocalcado)
      : null;
    const tamanhoCamisaBruto = texto(req.body?.tamanhocamisa || req.body?.tamanho_camisa);
    const tamanho_camisa = tamanhoCamisaBruto ? tamanhoCamisaBruto.toUpperCase() : null;
    const tamanho_calca = texto(req.body?.tamanhocalca || req.body?.tamanho_calca);

    const sexoBruto = texto(req.body?.sexo);
    const sexo = sexoBruto ? sexoBruto.toUpperCase() : null;

    const temFilhosBruto = texto(req.body?.temfilhos || req.body?.tem_filhos);
    const tem_filhos = temFilhosBruto ? temFilhosBruto.toUpperCase() : 'NAO';

    const quantidade_filhos = tem_filhos === 'SIM' && String(req.body?.quantidadefilhos ?? req.body?.quantidade_filhos ?? '').trim() !== ''
      ? Number(req.body?.quantidadefilhos ?? req.body?.quantidade_filhos)
      : null;

    const filhos = tem_filhos === 'SIM'
      ? JSON.stringify(Array.isArray(req.body?.filhos) ? req.body.filhos : [])
      : null;

    const [emailExistente] = await pool.query(
      `SELECT ID FROM SF_USUARIO WHERE CPF = ? LIMIT 1`,
      [cpf]
    );

    if (emailExistente.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Já existe usuário com este CPF cadastrado.'
      });
    }

    const senhaHash = await bcrypt.hash(senha, 12);

    const [result] = await pool.query(`
      INSERT INTO SF_USUARIO (
        NOME,
        EMAIL,
        SENHA,
        TELEFONE,
        PERFIL,
        SETOR,
        FUNCAO,
        DATA_ADMISSAO,
        CENTRO_CUSTO,
        LOCAL_TRABALHO,
        STATUS,
        CPF,
        RG,
        CNH,
        CNH_CATEGORIA,
        CNH_VALIDADE,
        CNH_ARQUIVO,
        DATA_NASCIMENTO,
        ESTADO_CIVIL,
        TELEFONE_PESSOAL,
        EMAIL_PESSOAL,
        FOTO,
        APELIDO,
        NUMERO_CALCADO,
        TAMANHO_CAMISA,
        TAMANHO_CALCA,
        SEXO,
        TEM_FILHOS,
        QUANTIDADE_FILHOS,
        FILHOS,
        MUST_CHANGE_PASSWORD
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `, [
      nome,
      email,
      senhaHash,
      telefone || null,
      perfil,
      setor,
      funcao || null,
      data_admissao,
      centro_custo || null,
      local_trabalho || null,
      status,
      cpf || null,
      rg || null,
      cnh || null,
      cnh_categoria || null,
      cnh_validade,
      cnh_arquivo || null,
      data_nascimento,
      estado_civil || null,
      telefone_pessoal || null,
      email_pessoal || null,
      foto || null,
      apelido || null,
      Number.isFinite(numero_calcado) ? numero_calcado : null,
      tamanho_camisa || null,
      tamanho_calca || null,
      sexo || null,
      tem_filhos,
      Number.isFinite(quantidade_filhos) ? quantidade_filhos : null,
      filhos
    ]);

    res.status(201).json({
      success: true,
      item: {
        id: result.insertId,
        nome,
        email
      }
    });
  } catch (err) {
    res.status(500).json({
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
    const data_admissao = nullableDate(req.body?.dataadmissao || req.body?.data_admissao);

    const centro_custo = titleCaseNome(req.body?.localtrabalho || req.body?.local_trabalho || req.body?.centro_custo);
    const local_trabalho = titleCaseNome(req.body?.unidadetrabalho || req.body?.unidade_trabalho || req.body?.local_trabalho);

    const status = texto(req.body?.status) || 'Ativo';

    const cpf = somenteNumeros(req.body?.cpf);
    const rg = texto(req.body?.rg);
    const cnh = texto(req.body?.cnh);

    const cnhCategoriaBruta = texto(req.body?.cnh_categoria || req.body?.cnhcategoria);
    const cnh_categoria = cnhCategoriaBruta ? cnhCategoriaBruta.toUpperCase() : null;

    const cnh_validade = nullableDate(req.body?.cnh_validade || req.body?.cnhvalidade);
    const cnh_arquivo = req.body?.cnh_arquivo ?? req.body?.cnharquivo;
    const data_nascimento = nullableDate(req.body?.data_nascimento || req.body?.datanascimento);
    const estado_civil = texto(req.body?.estado_civil || req.body?.estadocivil);
    const telefone_pessoal = somenteNumeros(req.body?.telefone_pessoal || req.body?.telefonepessoal);

    const email_pessoal_bruto = req.body?.email_pessoal ?? req.body?.emailpessoal;
    const email_pessoal = texto(email_pessoal_bruto) ? normalizarEmail(email_pessoal_bruto) : null;

    const foto = req.body?.foto;
    const apelido = texto(req.body?.apelido);

    const numero_calcado = String(req.body?.numero_calcado ?? '').trim() !== ''
      ? Number(req.body?.numero_calcado)
      : null;

    const tamanhoCamisaBruto = texto(req.body?.tamanhocamisa || req.body?.tamanho_camisa);
    const tamanho_camisa = tamanhoCamisaBruto ? tamanhoCamisaBruto.toUpperCase() : null;
    const tamanho_calca = texto(req.body?.tamanhocalca || req.body?.tamanho_calca);

    const sexoBruto = texto(req.body?.sexo);
    const sexo = sexoBruto ? sexoBruto.toUpperCase() : null;

    const temFilhosBruto = texto(req.body?.temfilhos || req.body?.tem_filhos);
    const tem_filhos = temFilhosBruto ? temFilhosBruto.toUpperCase() : 'NAO';

    const quantidade_filhos = tem_filhos === 'SIM' && String(req.body?.quantidadefilhos ?? req.body?.quantidade_filhos ?? '').trim() !== ''
      ? Number(req.body?.quantidadefilhos ?? req.body?.quantidade_filhos)
      : null;

    const filhos = tem_filhos === 'SIM'
      ? JSON.stringify(Array.isArray(req.body?.filhos) ? req.body.filhos : [])
      : null;

    const [rows] = await pool.query(
      `SELECT ID, FOTO, CNH_ARQUIVO FROM SF_USUARIO WHERE ID = ? LIMIT 1`,
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    const atual = rows[0];

    const [cpfExistente] = await pool.query(
      `SELECT ID FROM SF_USUARIO WHERE CPF = ? AND ID <> ? LIMIT 1`,
      [cpf, id]
    );

    if (cpfExistente.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro usuário com este CPF.'
      });
    }

    let fotoFinal = atual.FOTO ?? null;
    if (foto === null) fotoFinal = null;
    else if (typeof foto === 'string' && foto.trim() !== '') fotoFinal = foto.trim();

    let cnhArquivoFinal = atual.CNH_ARQUIVO ?? null;
    if (cnh_arquivo === null) cnhArquivoFinal = null;
    else if (typeof cnh_arquivo === 'string' && cnh_arquivo.trim() !== '') cnhArquivoFinal = cnh_arquivo.trim();

    const [result] = await pool.query(`
      UPDATE SF_USUARIO
         SET NOME = ?,
             EMAIL = ?,
             TELEFONE = ?,
             PERFIL = ?,
             SETOR = ?,
             FUNCAO = ?,
             DATA_ADMISSAO = ?,
             CENTRO_CUSTO = ?,
             LOCAL_TRABALHO = ?,
             STATUS = ?,
             CPF = ?,
             RG = ?,
             CNH = ?,
             CNH_CATEGORIA = ?,
             CNH_VALIDADE = ?,
             CNH_ARQUIVO = ?,
             DATA_NASCIMENTO = ?,
             ESTADO_CIVIL = ?,
             TELEFONE_PESSOAL = ?,
             EMAIL_PESSOAL = ?,
             FOTO = ?,
             APELIDO = ?,
             NUMERO_CALCADO = ?,
             TAMANHO_CAMISA = ?,
             TAMANHO_CALCA = ?,
             SEXO = ?,
             TEM_FILHOS = ?,
             QUANTIDADE_FILHOS = ?,
             FILHOS = ?
       WHERE ID = ?
    `, [
      nome,
      email,
      telefone || null,
      perfil,
      setor,
      funcao || null,
      data_admissao,
      centro_custo || null,
      local_trabalho || null,
      status,
      cpf || null,
      rg || null,
      cnh || null,
      cnh_categoria || null,
      cnh_validade,
      cnhArquivoFinal,
      data_nascimento,
      estado_civil || null,
      telefone_pessoal || null,
      email_pessoal || null,
      fotoFinal,
      apelido || null,
      Number.isFinite(numero_calcado) ? numero_calcado : null,
      tamanho_camisa || null,
      tamanho_calca || null,
      sexo || null,
      tem_filhos,
      Number.isFinite(quantidade_filhos) ? quantidade_filhos : null,
      filhos,
      id
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    try {
      if (foto === null && atual.FOTO) {
        const nomeArq = extrairNomeArquivoDeUrlPossivel(atual.FOTO);
        if (nomeArq) await apagarArquivoSeExistir(path.join(PASTAFOTOUSUARIO, nomeArq));
      }

      if (typeof foto === 'string' && foto.trim() && atual.FOTO && atual.FOTO !== foto.trim()) {
        const nomeArq = extrairNomeArquivoDeUrlPossivel(atual.FOTO);
        if (nomeArq) await apagarArquivoSeExistir(path.join(PASTAFOTOUSUARIO, nomeArq));
      }

      if (cnh_arquivo === null && atual.CNH_ARQUIVO) {
        const nomeArq = extrairNomeArquivoDeUrlPossivel(atual.CNH_ARQUIVO);
        if (nomeArq) await apagarArquivoSeExistir(path.join(PASTACNHUSUARIO, nomeArq));
      }

      if (typeof cnh_arquivo === 'string' && cnh_arquivo.trim() && atual.CNH_ARQUIVO && atual.CNH_ARQUIVO !== cnh_arquivo.trim()) {
        const nomeArq = extrairNomeArquivoDeUrlPossivel(atual.CNH_ARQUIVO);
        if (nomeArq) await apagarArquivoSeExistir(path.join(PASTACNHUSUARIO, nomeArq));
      }
    } catch (cleanupErr) {
      console.error('Usuário atualizado, mas falhou ao limpar arquivos antigos:', cleanupErr);
    }

    return res.json({ success: true, message: 'Usuário atualizado com sucesso.' });
  } catch (err) {
    console.error('Erro PUT /api/gestao-usuarios/:id', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar usuário.',
      error: err.message
    });
  }
});

app.get('/api/gestao-usuarios', async (req, res) => {
  try {
    const busca = texto(req.query?.q);

    let sql = `
      SELECT
        ID,
        NOME,
        EMAIL,
        TELEFONE,
        PERFIL,
        SETOR,
        FUNCAO,
        DATA_ADMISSAO AS DATAADMISSAO,
        CENTRO_CUSTO AS LOCALTRABALHO,
        LOCAL_TRABALHO AS UNIDADETRABALHO,
        STATUS,
        CPF,
        RG,
        CNH,
        CNH_CATEGORIA AS CNHCATEGORIA,
        CNH_VALIDADE AS CNHVALIDADE,
        CNH_ARQUIVO AS CNHARQUIVO,
        DATA_NASCIMENTO AS DATANASCIMENTO,
        ESTADO_CIVIL AS ESTADOCIVIL,
        TELEFONE_PESSOAL AS TELEFONEPESSOAL,
        EMAIL_PESSOAL AS EMAILPESSOAL,
        FOTO,
        APELIDO,
        NUMERO_CALCADO AS NUMEROCALCADO,
        TAMANHO_CAMISA AS TAMANHOCAMISA,
        TAMANHO_CALCA AS TAMANHOCALCA,
        SEXO,
        TEM_FILHOS AS TEMFILHOS,
        QUANTIDADE_FILHOS AS QUANTIDADEFILHOS,
        FILHOS
      FROM SF_USUARIO
    `;

    const params = [];

    if (busca) {
      sql += `
        WHERE
          NOME LIKE ?
          OR EMAIL LIKE ?
          OR PERFIL LIKE ?
          OR SETOR LIKE ?
      `;
      const like = `%${busca}%`;
      params.push(like, like, like, like);
    }

    sql += ` ORDER BY NOME ASC`;

    const [rows] = await pool.query(sql, params);
    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar usuários.',
      error: err.message
    });
  }
});

app.get('/api/gestao-usuarios/:id(\\d+)', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const [rows] = await pool.query(
      `SELECT
         ID,
         NOME,
         EMAIL,
         TELEFONE,
         PERFIL,
         SETOR,
         FUNCAO,
         DATA_ADMISSAO AS DATAADMISSAO,
         CENTRO_CUSTO AS LOCALTRABALHO,
         LOCAL_TRABALHO AS UNIDADETRABALHO,
         STATUS,
         CPF,
         RG,
         CNH,
         CNH_CATEGORIA AS CNHCATEGORIA,
         CNH_VALIDADE AS CNHVALIDADE,
         CNH_ARQUIVO AS CNHARQUIVO,
         DATA_NASCIMENTO AS DATANASCIMENTO,
         ESTADO_CIVIL AS ESTADOCIVIL,
         TELEFONE_PESSOAL AS TELEFONEPESSOAL,
         EMAIL_PESSOAL AS EMAILPESSOAL,
         FOTO,
         APELIDO,
         NUMERO_CALCADO AS NUMEROCALCADO,
         TAMANHO_CAMISA AS TAMANHOCAMISA,
         TAMANHO_CALCA AS TAMANHOCALCA,
         SEXO,
         TEM_FILHOS AS TEMFILHOS,
         QUANTIDADE_FILHOS AS QUANTIDADEFILHOS,
         FILHOS
       FROM SF_USUARIO
       WHERE ID = ?
       LIMIT 1`,
      [id]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
    }

    res.json({ success: true, item: rows[0] });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao buscar usuário.',
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

app.post('/api/gestao-usuarios-locais-trabalho', async (req, res) => {
  try {
    const nome = titleCaseNome(req.body?.nome || '');
    const endereco = String(req.body?.endereco || '').trim();
    const telefone = String(req.body?.telefone || '').trim();

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome da unidade de trabalho é obrigatório.'
      });
    }

    const [r] = await pool.query(
      `INSERT INTO SF_LOCAL_TRABALHO (NOME, ENDERECO, TELEFONE) VALUES (?, ?, ?)`,
      [nome, endereco || null, telefone || null]
    );

    return res.status(201).json({
      success: true,
      item: {
        id: r.insertId,
        nome,
        endereco,
        telefone
      }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao adicionar unidade de trabalho.',
      error: err.message
    });
  }
});

app.get('/api/gestao-usuarios-locais-trabalho', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT ID, NOME, ENDERECO, TELEFONE
      FROM SF_LOCAL_TRABALHO
      WHERE NOME IS NOT NULL AND NOME <> ''
      ORDER BY NOME ASC
    `);

    res.json({ success: true, items: rows });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar unidades de trabalho.',
      error: err.message
    });
  }
});

app.put('/api/gestao-usuarios-locais-trabalho/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const nome = titleCaseNome(req.body?.nome || '');
    const endereco = String(req.body?.endereco || '').trim();
    const telefone = String(req.body?.telefone || '').trim();

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID da unidade de trabalho inválido.'
      });
    }

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome da unidade de trabalho é obrigatório.'
      });
    }

    const [r] = await pool.query(
      `
      UPDATE SF_LOCAL_TRABALHO
         SET NOME = ?, ENDERECO = ?, TELEFONE = ?
       WHERE ID = ?
      `,
      [nome, endereco || null, telefone || null, id]
    );

    if (!r.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Unidade de trabalho não encontrada.'
      });
    }

    return res.json({
      success: true,
      item: { id, nome, endereco, telefone }
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao editar unidade de trabalho.',
      error: err.message
    });
  }
});

app.delete('/api/gestao-usuarios-locais-trabalho/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID da unidade de trabalho inválido.'
      });
    }

    const [r] = await pool.query(
      `DELETE FROM SF_LOCAL_TRABALHO WHERE ID = ?`,
      [id]
    );

    if (!r.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Unidade de trabalho não encontrada.'
      });
    }

    return res.json({
      success: true,
      message: 'Unidade de trabalho excluída com sucesso.'
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir unidade de trabalho.',
      error: err.message
    });
  }
});

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

app.patch('/api/marketing/cards/:id/exibido', async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ success: false, message: 'ID inválido.' });
    }

    await pool.query(
      `UPDATE SFMARKETINGIMAGEM
       SET ULTIMAEXIBICAOEM = NOW()
       WHERE ID = ?`,
      [id]
    );

    return res.json({ success: true });
  } catch (err) {
    console.error('Erro ao marcar card como exibido', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao marcar card como exibido.',
      error: err.message
    });
  }
});

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

app.post('/api/marketing/cards', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Imagem não enviada.' });
    }

    const titulo = String(req.body?.titulo || '').trim() || null;
    const descricao = String(req.body?.descricao || '').trim() || null;
    const card = String(req.body?.card || 'principal').trim();
    const exibirNoPainel = String(req.body?.exibirNoPainel || '1') === '1' ? 1 : 0;
    const ativo = String(req.body?.ativo || '1') === '1' ? 1 : 0;
    const dataInicio = String(req.body?.dataInicio || '').trim() || null;
    const dataFim = String(req.body?.dataFim || '').trim() || null;
    const recorrencia = String(req.body?.recorrencia || 'once').trim();
    const apenasUmaVez = String(req.body?.apenasUmaVez || '0') === '1' ? 1 : 0;
    const ordem = Number(req.body?.ordem || 0) || 0;

    const url = `/anexos/marketing/${encodeURIComponent(req.file.filename)}`;

    const [r] = await pool.query(`
      INSERT INTO SF_MARKETING_IMAGEM (
        NOME_ARQUIVO, URL, TITULO, DESCRICAO, CARD,
        ATIVO, EXIBIR_NO_PAINEL, DATA_INICIO, DATA_FIM,
        RECORRENCIA, APENAS_UMA_VEZ, ORDEM
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      req.file.filename,
      url,
      titulo,
      descricao,
      card,
      ativo,
      exibirNoPainel,
      dataInicio,
      dataFim,
      recorrencia,
      apenasUmaVez,
      ordem
    ]);

    return res.status(201).json({
      success: true,
      item: {
        id: r.insertId,
        name: req.file.filename,
        url
      }
    });
  } catch (err) {
    console.error('Erro ao salvar card de marketing:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar card de marketing.',
      error: err.message
    });
  }
});

app.get('/api/marketing/painel', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ID,
        TITULO,
        DESCRICAO,
        CARD,
        URL,
        ATIVO,
        EXIBIR_NO_PAINEL AS EXIBIRNOPAINEL,
        DATA_INICIO AS DATAINICIO,
        DATA_FIM AS DATAFIM,
        RECORRENCIA,
        APENAS_UMA_VEZ AS APENASUMAVEZ,
        ULTIMA_EXIBICAO_EM AS ULTIMAEXIBICAOEM,
        ORDEM
      FROM SF_MARKETING_IMAGEM
      WHERE ATIVO = 1
        AND EXIBIR_NO_PAINEL = 1
      ORDER BY ORDEM ASC, ID DESC
    `);

    const hoje = new Date();
    const yyyy = hoje.getFullYear();
    const mm = String(hoje.getMonth() + 1).padStart(2, '0');
    const dd = String(hoje.getDate()).padStart(2, '0');
    const hojeStr = `${yyyy}-${mm}-${dd}`;

    const ativos = rows.filter(item => {
    const inicio = toDateOnly(item.DATAINICIO);
    const fim = toDateOnly(item.DATAFIM);
    const rec = String(item.RECORRENCIA || 'once').toLowerCase().trim();
    const apenasUmaVez = Number(item.APENASUMAVEZ || 0) === 1;
    const jaExibido = !!item.ULTIMAEXIBICAOEM;


    if (inicio && hojeStr < inicio) return false;
    if (fim && hojeStr > fim) return false;

    if (rec === 'always') return true;

    if (rec === 'daily') {
      return !apenasUmaVez || !jaExibido;
    }

    if (rec === 'once') {
      if (!inicio) return true;
      if (hojeStr !== inicio) return false;
      return !apenasUmaVez || !jaExibido;
    }

    if (rec === 'monthly') {
      if (!inicio) return false;
      const [, , diaI] = inicio.split('-').map(Number);
      if (Number(dd) !== diaI) return false;
      return !apenasUmaVez || !jaExibido;
    }

    if (rec === 'yearly') {
      if (!inicio) return false;
      const [, mesI, diaI] = inicio.split('-').map(Number);
      if (Number(dd) !== diaI || Number(mm) !== mesI) return false;
      return !apenasUmaVez || !jaExibido;
    }

    return false;
  });



    return res.json({
      success: true,
      items: ativos.map(item => ({
        id: item.ID,
        titulo: item.TITULO,
        descricao: item.DESCRICAO,
        card: item.CARD,
        url: item.URL,
        recorrencia: item.RECORRENCIA,
        apenasUmaVez: Number(item.APENASUMAVEZ || 0)
      }))
    });
  } catch (err) {
    console.error('Erro /api/marketing/painel:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar cards do painel.',
      error: err.message
    });
  }
});

function toDateOnly(value) {
  if (!value) return null;

  if (value instanceof Date) {
    const y = value.getFullYear();
    const m = String(value.getMonth() + 1).padStart(2, '0');
    const d = String(value.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }

  const s = String(value).trim();
  const iso = s.match(/^(\d{4}-\d{2}-\d{2})/);
  if (iso) return iso[1];

  const dt = new Date(s);
  if (!Number.isNaN(dt.getTime())) {
    const y = dt.getFullYear();
    const m = String(dt.getMonth() + 1).padStart(2, '0');
    const d = String(dt.getDate()).padStart(2, '0');
    return `${y}-${m}-${d}`;
  }

  return null;
}

app.get('/api/marketing/cards', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ID,
        NOME_ARQUIVO,
        URL,
        TITULO,
        DESCRICAO,
        CARD,
        ATIVO,
        EXIBIR_NO_PAINEL AS EXIBIRNOPAINEL,
        DATA_INICIO AS DATAINICIO,
        DATA_FIM AS DATAFIM,
        RECORRENCIA,
        APENAS_UMA_VEZ AS APENASUMAVEZ,
        ORDEM,
        ULTIMA_EXIBICAO_EM
      FROM SF_MARKETING_IMAGEM
      ORDER BY ORDEM ASC, ID DESC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar cards de marketing:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar cards de marketing.',
      error: err.message
    });
  }
});

app.put('/api/marketing/cards/:id', upload.single('file'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT ID, NOME_ARQUIVO, URL
      FROM SF_MARKETING_IMAGEM
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Card não encontrado.'
      });
    }

    const atual = rows[0];

    const titulo = String(req.body?.titulo || '').trim() || null;
    const descricao = String(req.body?.descricao || '').trim() || null;
    const card = String(req.body?.card || 'principal').trim();
    const exibirNoPainel = String(req.body?.exibirNoPainel || '1') === '1' ? 1 : 0;
    const ativo = String(req.body?.ativo || '1') === '1' ? 1 : 0;
    const dataInicio = String(req.body?.dataInicio || '').trim() || null;
    const dataFim = String(req.body?.dataFim || '').trim() || null;
    const recorrencia = String(req.body?.recorrencia || 'once').trim();
    const apenasUmaVez = String(req.body?.apenasUmaVez || '0') === '1' ? 1 : 0;
    const ordem = Number(req.body?.ordem || 0) || 0;

    let nomeArquivo = atual.NOME_ARQUIVO;
    let url = atual.URL;

    if (req.file) {
      nomeArquivo = req.file.filename;
      url = `/anexos/marketing/${encodeURIComponent(req.file.filename)}`;
    }

    await pool.query(`
      UPDATE SF_MARKETING_IMAGEM
      SET
        NOME_ARQUIVO = ?,
        URL = ?,
        TITULO = ?,
        DESCRICAO = ?,
        CARD = ?,
        ATIVO = ?,
        EXIBIR_NO_PAINEL = ?,
        DATA_INICIO = ?,
        DATA_FIM = ?,
        RECORRENCIA = ?,
        APENAS_UMA_VEZ = ?,
        ORDEM = ?
      WHERE ID = ?
    `, [
      nomeArquivo,
      url,
      titulo,
      descricao,
      card,
      ativo,
      exibirNoPainel,
      dataInicio,
      dataFim,
      recorrencia,
      apenasUmaVez,
      ordem,
      id
    ]);

    return res.json({
      success: true,
      item: {
        id,
        name: nomeArquivo,
        url
      }
    });
  } catch (err) {
    console.error('Erro ao atualizar card de marketing:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar card de marketing.',
      error: err.message
    });
  }
});


// Cadastro CLientes

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
//cron.schedule('0 6 * * *', () => {
  //processarEmailsOffice365();
//});

// todos os dias às 20:00
//cron.schedule('0 20 * * *', () => {
  //processarEmailsOffice365();
//});

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

app.post('/api/estoque/importacao-manual', async (req, res) => {
  const conn = await pool.getConnection();

  try {
    const usuarioRegistro = textoLivre(req.body?.usuarioRegistro);
    const local = textoLivre(req.body?.local).toUpperCase() || null;
    const idLocalAlmoxarifado = 7 || null;
    const itens = Array.isArray(req.body?.itens) ? req.body.itens : [];

    if (!idLocalAlmoxarifado) {
      return res.status(400).json({
        success: false,
        message: 'Local de armazenagem é obrigatório.'
      });
    }

    if (!itens.length) {
      return res.status(400).json({
        success: false,
        message: 'Nenhum item informado para lançamento manual.'
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

    const nomeLocal = textoLivre(localSelecionado.NOME).toUpperCase() || local || 'MANUAL';

    const itensProcessados = [];

    for (const item of itens) {
      const idProduto = Number(item.idproduto || item.id_produto);
      const codProdutoSistema = textoLivre(item.codprodutosistema || item.cod_produto_sistema).toUpperCase();
      const descricaoProdutoSistema = textoLivre(
        item.descricaoprodutosistema || item.descricao_produto_sistema
      ).toUpperCase() || null;
      const unidade = textoLivre(item.unidade).toUpperCase() || null;
      const qtd = parseDecimalBr(item.quantidade);
      const valorUnit = parseDecimalBr(item.valorUnitario || 0);
      const valorTotalInformado = parseDecimalBr(item.valorTotal || 0);
      const valorTotal = valorTotalInformado > 0 ? valorTotalInformado : (qtd * valorUnit);

      if (!idProduto) {
        throw new Error('Existe item sem produto do sistema vinculado.');
      }

      if (!codProdutoSistema) {
        throw new Error(`O item ${idProduto} está sem código do produto do sistema.`);
      }

      if (!unidade) {
        throw new Error(`O item ${codProdutoSistema} está sem unidade informada.`);
      }

      if (!qtd || qtd <= 0) {
        throw new Error(`O item ${codProdutoSistema} está com quantidade inválida.`);
      }

      const [produtoRows] = await conn.query(
        `
        SELECT id, codigo, descricao, unidade, ativo
        FROM SF_PRODUTOS
        WHERE id = ?
          AND ativo = 1
        LIMIT 1
        `,
        [idProduto]
      );

      const produtoSistema = produtoRows[0] || null;

      if (!produtoSistema) {
        throw new Error(`Produto do sistema não encontrado para o item ${codProdutoSistema}.`);
      }

      const codigoProdutoFinal = textoLivre(produtoSistema.codigo).toUpperCase() || codProdutoSistema;
      const descricaoProdutoFinal =
        textoLivre(produtoSistema.descricao).toUpperCase() || descricaoProdutoSistema || null;
      const unidadeFinal = unidade || textoLivre(produtoSistema.unidade).toUpperCase() || null;

      const payloadEntradaLog = {
        fornecedor_id: null,
        nota: 'MANUAL',
        serie: null,
        cnpj_emitente: null,
        cnpj_remetente: null,
        data_emissao: null,
        usuario_registro: usuarioRegistro || null,
        qtd_nf: qtd,
        valor_unitario_nf: valorUnit,
        valor_total_nf: valorTotal,
        cod_produto_nf: codigoProdutoFinal,
        descricao_produto_nf: descricaoProdutoFinal,
        unidade_nf: unidadeFinal,
        cod_produto_sistema: codigoProdutoFinal,
        descricao_produto_sistema: descricaoProdutoFinal,
        produto_sistema_id: idProduto,
        local: nomeLocal,
        id_local_almoxarifado: idLocalAlmoxarifado,
        origem: 'MANUAL'
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
          null,
          'MANUAL',
          null,
          null,
          null,
          null,
          usuarioRegistro || null,
          qtd,
          valorUnit,
          valorTotal,
          codigoProdutoFinal,
          descricaoProdutoFinal,
          unidadeFinal,
          codigoProdutoFinal,
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
        observacao: 'Registro criado via lançamento manual'
      });

      itensProcessados.push({
        idEntrada: rEntrada.insertId,
        idproduto: idProduto,
        codprodutosistema: codigoProdutoFinal,
        descricaoprodutosistema: descricaoProdutoFinal,
        unidade: unidadeFinal,
        quantidade: qtd
      });
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Lançamento manual realizado com sucesso.',
      itensProcessados
    });
  } catch (err) {
    try { await conn.rollback(); } catch {}
    console.error('Erro /api/estoque/importacao-manual:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao realizar lançamento manual.',
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
      usuarioDb.CENTRO_CUSTO ?? usuarioDb.CENTRO_CUSTO ?? ''
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
      usuarioDb.CENTRO_CUSTO ?? usuarioDb.CENTRO_CUSTO ?? ''
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
        u.CENTRO_CUSTO
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

    const centroCustoUsuario = String(usuarioDb.CENTRO_CUSTO ?? '').trim().toUpperCase();

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
        t.ID_PRODUTO AS IDPRODUTO,
        t.ID_ENTRADA_ORIGEM AS IDENTRADAORIGEM,
        p.codigo AS CODIGOPRODUTO,
        p.descricao AS DESCRICAOPRODUTO,
        COALESCE(t.UNIDADE, p.unidade, 'UN') AS UNIDADE,
        t.ID_LOCAL_ORIGEM AS IDLOCALORIGEM,
        COALESCE(loa.NOME, lot.NOME) AS LOCALORIGEM,
        t.ID_LOCAL_DESTINO AS IDLOCALDESTINO,
        ld.NOME AS LOCALDESTINO,
        t.QUANTIDADE,
        t.OBSERVACAO,
        t.TIPO_TRANSFERENCIA AS TIPOTRANSFERENCIA,
        t.RESPONSAVEL_TRANSPORTE AS RESPONSAVELTRANSPORTE,
        t.RESPONSAVEL_ENTREGA AS RESPONSAVELENTREGA,
        t.USUARIO_RECEBIMENTO AS USUARIORECEBIMENTO,
        t.DATA_HORA_RECEBIMENTO AS DATAHORARECEBIMENTO,
        t.STATUS_TRANSFERENCIA AS STATUSTRANSFERENCIA,
        t.USUARIO_CADASTRO AS USUARIOCADASTRO,
        t.DATA_CADASTRO AS DATACADASTRO,
        t.USUARIO_ALTERACAO AS USUARIOALTERACAO,
        t.DATA_ALTERACAO AS DATAALTERACAO
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
        p.id AS IDPRODUTO,
        p.codigo AS CODIGOPRODUTO,
        p.descricao AS DESCRICAOPRODUTO,
        COALESCE(p.unidade, 'UN') AS UNIDADE,

        centro.ID AS IDLOCALDESTINO,
        centro.NOME AS LOCALDESTINO,

        COALESCE(rec.qtd_recebida, 0) AS QTDRECEBIDA,
        COALESCE(env.qtd_enviada, 0) AS QTDENVIADA,
        COALESCE(pend.qtd_transferida_nao_recebida, 0) AS QTDTRANSFERIDANAORECEBIDA,

        COALESCE(saida.qtd_saida, 0) AS QTDSAIDA,
        COALESCE(dev.qtd_devolvida, 0) AS QTDDEVOLVIDA,

        CASE
          WHEN COALESCE(saida.qtd_saida, 0) - COALESCE(dev.qtd_devolvida, 0) < 0 THEN 0
          ELSE COALESCE(saida.qtd_saida, 0) - COALESCE(dev.qtd_devolvida, 0)
        END AS QTDSAIDALIQUIDA,

        CASE
          WHEN
            COALESCE(rec.qtd_recebida, 0)
            - COALESCE(env.qtd_enviada, 0)
            - COALESCE(saida.qtd_saida, 0)
            + COALESCE(dev.qtd_devolvida, 0) < 0
          THEN 0
          ELSE
            COALESCE(rec.qtd_recebida, 0)
            - COALESCE(env.qtd_enviada, 0)
            - COALESCE(saida.qtd_saida, 0)
            + COALESCE(dev.qtd_devolvida, 0)
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

      LEFT JOIN (
        SELECT
          s.ID_PRODUTO,
          SUM(COALESCE(s.QUANTIDADE, 0)) AS qtd_saida
        FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
        WHERE s.ID_LOCAL_ORIGEM = ?
        GROUP BY s.ID_PRODUTO
      ) saida ON saida.ID_PRODUTO = p.id

      LEFT JOIN (
        SELECT
          s.ID_PRODUTO,
          SUM(COALESCE(d.QUANTIDADE, 0)) AS qtd_devolvida
        FROM SF_ESTOQUE_SAIDA_DEVOLUCAO d
        INNER JOIN SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
          ON s.ID = d.ID_SAIDA
        WHERE s.ID_LOCAL_ORIGEM = ?
        GROUP BY s.ID_PRODUTO
      ) dev ON dev.ID_PRODUTO = p.id

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
      OR EXISTS (
        SELECT 1
        FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
        WHERE s.ID_PRODUTO = p.id
          AND s.ID_LOCAL_ORIGEM = ?
      )

      ORDER BY p.codigo ASC, p.descricao ASC
      `,
      [
        centro.ID, // rec
        centro.ID, // env
        centro.ID, // pend
        centro.ID, // saida
        centro.ID, // dev
        centro.ID, // centro cross
        centro.ID, // exists transferencia destino
        centro.ID, // exists transferencia origem
        centro.ID  // exists saida
      ]
    );

    return res.json({
      success: true,
      usuario,
      usuarioId: usuarioDb.ID,
      usuarioNome: usuarioDb.nome,
      centroCusto: centroCustoUsuario,
      centroCustoId: centro.ID,
      centroCustoNome: centro.NOME,
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

async function obterSaldoCentroCusto(conn, idProduto, idLocalOrigem, ignoreTransferenciaId = null, ignoreSaidaId = null) {
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

  const paramsSaidas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlSaidas = `
    SELECT COALESCE(SUM(COALESCE(s.QUANTIDADE, 0)), 0) AS qtd_saida
    FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
    WHERE s.ID_PRODUTO = ?
      AND s.ID_LOCAL_ORIGEM = ?
  `;

  if (ignoreSaidaId) {
    sqlSaidas += ' AND s.ID <> ?';
    paramsSaidas.push(Number(ignoreSaidaId));
  }

  const [rowsSaidas] = await conn.query(sqlSaidas, paramsSaidas);

  const paramsDevolvidas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlDevolvidas = `
    SELECT COALESCE(SUM(COALESCE(d.QUANTIDADE, 0)), 0) AS qtd_devolvida
    FROM SF_ESTOQUE_SAIDA_DEVOLUCAO d
    INNER JOIN SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
      ON s.ID = d.ID_SAIDA
    WHERE s.ID_PRODUTO = ?
      AND s.ID_LOCAL_ORIGEM = ?
  `;

  if (ignoreSaidaId) {
    sqlDevolvidas += ' AND s.ID <> ?';
    paramsDevolvidas.push(Number(ignoreSaidaId));
  }

  const [rowsDevolvidas] = await conn.query(sqlDevolvidas, paramsDevolvidas);

  const qtdRecebida = Number(rowsRecebidas?.[0]?.qtd_recebida ?? 0);
  const qtdEnviada = Number(rowsEnviadas?.[0]?.qtd_enviada ?? 0);
  const qtdSaida = Number(rowsSaidas?.[0]?.qtd_saida ?? 0);
  const qtdDevolvida = Number(rowsDevolvidas?.[0]?.qtd_devolvida ?? 0);

  const saldo = qtdRecebida - qtdEnviada - qtdSaida + qtdDevolvida;

  return {
    qtdRecebida,
    qtdEnviada,
    qtdSaida,
    qtdDevolvida,
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

async function obterSaldoCentroCustoComSaidas(conn, idProduto, idLocalOrigem, ignoreSaidaId = null) {
  const saldoBase = await obterSaldoCentroCusto(conn, idProduto, idLocalOrigem);

  const paramsSaidas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlSaidas = `
    SELECT COALESCE(SUM(COALESCE(s.QUANTIDADE, 0)), 0) AS qtd_saida
    FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
    WHERE s.ID_PRODUTO = ?
      AND s.ID_LOCAL_ORIGEM = ?
  `;

  if (ignoreSaidaId) {
    sqlSaidas += ' AND s.ID <> ?';
    paramsSaidas.push(Number(ignoreSaidaId));
  }

  const [rowsSaidas] = await conn.query(sqlSaidas, paramsSaidas);

  const paramsDevolvidas = [Number(idProduto), Number(idLocalOrigem)];
  let sqlDevolvidas = `
    SELECT COALESCE(SUM(COALESCE(d.QUANTIDADE, 0)), 0) AS qtd_devolvida
    FROM SF_ESTOQUE_SAIDA_DEVOLUCAO d
    INNER JOIN SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
      ON s.ID = d.ID_SAIDA
    WHERE s.ID_PRODUTO = ?
      AND s.ID_LOCAL_ORIGEM = ?
  `;

  if (ignoreSaidaId) {
    sqlDevolvidas += ' AND s.ID <> ?';
    paramsDevolvidas.push(Number(ignoreSaidaId));
  }

  const [rowsDevolvidas] = await conn.query(sqlDevolvidas, paramsDevolvidas);

  const qtdSaida = Number(rowsSaidas?.[0]?.qtd_saida ?? 0);
  const qtdDevolvida = Number(rowsDevolvidas?.[0]?.qtd_devolvida ?? 0);
  const saldo = Number(saldoBase?.saldo ?? 0) - qtdSaida + qtdDevolvida;

  return {
    qtdRecebida: Number(saldoBase?.qtdRecebida ?? 0),
    qtdEnviada: Number(saldoBase?.qtdEnviada ?? 0),
    qtdSaida,
    qtdDevolvida,
    saldo: saldo < 0 ? 0 : saldo
  };
}

async function obterResumoSaidaCentroCusto(conn, idSaida) {
  const [rows] = await conn.query(
    `
    SELECT
      s.*,
      COALESCE(SUM(COALESCE(d.QUANTIDADE, 0)), 0) AS QTD_DEVOLVIDA
    FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
    LEFT JOIN SF_ESTOQUE_SAIDA_DEVOLUCAO d
      ON d.ID_SAIDA = s.ID
    WHERE s.ID = ?
    GROUP BY s.ID
    LIMIT 1
    `,
    [Number(idSaida)]
  );

  const saida = rows[0] || null;
  if (!saida) return null;

  const quantidadeSaida = Number(saida.QUANTIDADE ?? 0);
  const qtdDevolvida = Number(saida.QTD_DEVOLVIDA ?? 0);
  const saldoPendente = Math.max(quantidadeSaida - qtdDevolvida, 0);

  let statusSaida = 'ATIVA';
  if (qtdDevolvida > 0 && saldoPendente > 0) statusSaida = 'PARCIALMENTE_DEVOLVIDA';
  if (saldoPendente === 0) statusSaida = 'DEVOLVIDA_TOTALMENTE';

  return {
    ...saida,
    QTD_DEVOLVIDA: qtdDevolvida,
    SALDO_PENDENTE: saldoPendente,
    STATUS_SAIDA: statusSaida
  };
}

async function inserirLogSaidaCentroCusto(conn, {
  idSaida,
  acao,
  saldoAntes,
  quantidadeSaida,
  saldoDepois,
  usuario,
  observacao
}) {
  await conn.query(
    `
    INSERT INTO SF_ESTOQUE_SAIDA_CENTRO_CUSTO_LOG
      (
        ID_SAIDA,
        ACAO,
        SALDO_ANTES,
        QUANTIDADE_SAIDA,
        SALDO_DEPOIS,
        USUARIO,
        OBSERVACAO
      )
    VALUES (?, ?, ?, ?, ?, ?, ?)
    `,
    [
      Number(idSaida),
      textolivreTr(acao, 50),
      parseDecimal(saldoAntes) || 0,
      parseDecimal(quantidadeSaida) || 0,
      parseDecimal(saldoDepois) || 0,
      textolivreTr(usuario, 150) || 'SISTEMA',
      textolivreTr(observacao, 255) || null
    ]
  );
}

async function inserirLogDevolucaoSaidaCentroCusto(conn, {
  idDevolucao,
  idSaida,
  acao,
  saldoSaidaAntes,
  quantidadeDevolvida,
  saldoSaidaDepois,
  usuario,
  observacao
}) {
  await conn.query(
    `
    INSERT INTO SF_ESTOQUE_SAIDA_DEVOLUCAO_LOG
      (
        ID_DEVOLUCAO,
        ID_SAIDA,
        ACAO,
        SALDO_SAIDA_ANTES,
        QUANTIDADE_DEVOLVIDA,
        SALDO_SAIDA_DEPOIS,
        USUARIO,
        OBSERVACAO
      )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
    [
      Number(idDevolucao),
      Number(idSaida),
      textolivreTr(acao, 50),
      parseDecimal(saldoSaidaAntes) || 0,
      parseDecimal(quantidadeDevolvida) || 0,
      parseDecimal(saldoSaidaDepois) || 0,
      textolivreTr(usuario, 150) || 'SISTEMA',
      textolivreTr(observacao, 255) || null
    ]
  );
}

app.get('/api/estoque/centro-custo/saidas', async (req, res) => {
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

    const [saidas] = await conn.query(
      `
      SELECT
        s.ID,
        s.ID_PRODUTO,
        s.ID_LOCAL_ORIGEM,
        p.codigo AS CODIGO_PRODUTO,
        p.descricao AS DESCRICAO_PRODUTO,
        COALESCE(s.UNIDADE, p.unidade, 'UN') AS UNIDADE,
        lo.NOME AS LOCAL_ORIGEM,
        s.QUANTIDADE,
        s.FINALIDADE,
        s.USUARIO_SOLICITANTE,
        s.OBSERVACAO,
        s.USUARIO_CADASTRO,
        s.DATA_CADASTRO,
        s.USUARIO_ALTERACAO,
        s.DATA_ALTERACAO
      FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
      INNER JOIN SF_PRODUTOS p
        ON p.id = s.ID_PRODUTO
      INNER JOIN SF_CENTRO_CUSTO lo
        ON lo.ID = s.ID_LOCAL_ORIGEM
      WHERE s.ID_PRODUTO = ?
        AND s.ID_LOCAL_ORIGEM = ?
      ORDER BY s.DATA_CADASTRO DESC, s.ID DESC
      `,
      [idProduto, idLocalOrigem]
    );

    const idsSaida = saidas.map(s => Number(s.ID)).filter(Boolean);

    let devolucoes = [];
    if (idsSaida.length) {
      const placeholders = idsSaida.map(() => '?').join(',');

      const [rowsDevolucoes] = await conn.query(
        `
        SELECT
          d.ID,
          d.ID_SAIDA,
          d.QUANTIDADE,
          d.OBSERVACAO,
          d.USUARIO_DEVOLUCAO,
          d.DATA_CADASTRO
        FROM SF_ESTOQUE_SAIDA_DEVOLUCAO d
        WHERE d.ID_SAIDA IN (${placeholders})
        ORDER BY d.DATA_CADASTRO DESC, d.ID DESC
        `,
        idsSaida
      );

      devolucoes = rowsDevolucoes;
    }

    const devolucoesPorSaida = devolucoes.reduce((acc, dev) => {
      const idSaida = Number(dev.ID_SAIDA);
      if (!acc[idSaida]) acc[idSaida] = [];
      acc[idSaida].push(dev);
      return acc;
    }, {});

    const items = saidas.map(saida => {
      const listaDevolucoes = devolucoesPorSaida[Number(saida.ID)] || [];
      const quantidadeSaida = Number(saida.QUANTIDADE ?? 0);
      const quantidadeDevolvida = listaDevolucoes.reduce(
        (total, d) => total + Number(d.QUANTIDADE ?? 0),
        0
      );
      const saldoPendente = Math.max(quantidadeSaida - quantidadeDevolvida, 0);

      let statusSaida = 'ATIVA';
      if (quantidadeDevolvida > 0 && saldoPendente > 0) {
        statusSaida = 'PARCIALMENTE_DEVOLVIDA';
      }
      if (saldoPendente === 0) {
        statusSaida = 'DEVOLVIDA_TOTALMENTE';
      }

      return {
        ...saida,
        QUANTIDADE_DEVOLVIDA: quantidadeDevolvida,
        SALDO_PENDENTE: saldoPendente,
        STATUS_SAIDA: statusSaida,
        devolucoes: listaDevolucoes
      };
    });

    const saldoInfo = await obterSaldoCentroCustoComSaidas(conn, idProduto, idLocalOrigem);

    return res.json({
      success: true,
      produto,
      localOrigem,
      saldo: saldoInfo.saldo,
      qtdRecebida: saldoInfo.qtdRecebida,
      qtdEnviada: saldoInfo.qtdEnviada,
      qtdSaida: saldoInfo.qtdSaida,
      qtdDevolvida: saldoInfo.qtdDevolvida,
      items
    });
  } catch (err) {
    console.error('Erro ao listar saídas do centro de custo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar saídas do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/estoque/centro-custo/saidas', async (req, res) => {
  let conn;

  try {
    const idProduto = Number(req.body.idProduto);
    const idLocalOrigem = Number(req.body.idLocalOrigem);
    const quantidade = parseDecimal(req.body.quantidade);
    const unidade = textolivreTr(req.body.unidade, 10);
    const finalidade = textolivreTr(req.body.finalidade, 255);
    const usuarioSolicitante = textolivreTr(req.body.usuarioSolicitante, 150);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    if (!idProduto || !idLocalOrigem) {
      return res.status(400).json({
        success: false,
        message: 'Informe idProduto e idLocalOrigem.'
      });
    }

    if (!(quantidade > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida para saída.'
      });
    }

    if (!finalidade) {
      return res.status(400).json({
        success: false,
        message: 'Informe a finalidade da utilização.'
      });
    }

    if (!usuarioSolicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário solicitante.'
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

    const saldoInfo = await obterSaldoCentroCustoComSaidas(conn, idProduto, idLocalOrigem);
    const saldoAntes = Number(saldoInfo.saldo ?? 0);

    if (quantidade > saldoAntes) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Quantidade excede o saldo disponível (${saldoAntes}).`
      });
    }

    const [result] = await conn.query(
      `
      INSERT INTO SF_ESTOQUE_SAIDA_CENTRO_CUSTO
        (
          ID_PRODUTO,
          ID_LOCAL_ORIGEM,
          QUANTIDADE,
          UNIDADE,
          FINALIDADE,
          USUARIO_SOLICITANTE,
          OBSERVACAO,
          USUARIO_CADASTRO
        )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idProduto,
        idLocalOrigem,
        quantidade,
        unidade || produto.unidade || 'UN',
        finalidade,
        usuarioSolicitante,
        observacao || null,
        usuario
      ]
    );

    const idSaida = result.insertId;
    const saldoDepois = saldoAntes - quantidade;

    await inserirLogSaidaCentroCusto(conn, {
      idSaida,
      acao: 'CRIACAO',
      saldoAntes,
      quantidadeSaida: quantidade,
      saldoDepois,
      usuario,
      observacao: observacao || 'Saída de material registrada.'
    });

    await conn.commit();

    return res.json({
      success: true,
      id: idSaida,
      message: 'Saída registrada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao registrar saída do centro de custo:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar saída do centro de custo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/centro-custo/saidas/:id/logs', async (req, res) => {
  let conn;

  try {
    const idSaida = Number(req.params.id);

    if (!idSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe o id da saída.'
      });
    }

    conn = await pool.getConnection();

    const saida = await obterResumoSaidaCentroCusto(conn, idSaida);
    if (!saida) {
      return res.status(404).json({
        success: false,
        message: 'Saída não encontrada.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        l.ID,
        l.ID_SAIDA,
        l.ACAO,
        l.SALDO_ANTES,
        l.QUANTIDADE_SAIDA,
        l.SALDO_DEPOIS,
        l.USUARIO,
        l.OBSERVACAO,
        l.DATA_HORA
      FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO_LOG l
      WHERE l.ID_SAIDA = ?
      ORDER BY l.DATA_HORA DESC, l.ID DESC
      `,
      [idSaida]
    );

    return res.json({
      success: true,
      item: saida,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar logs da saída:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar logs da saída.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/centro-custo/saidas/:id/devolucoes', async (req, res) => {
  let conn;

  try {
    const idSaida = Number(req.params.id);

    if (!idSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe o id da saída.'
      });
    }

    conn = await pool.getConnection();

    const saida = await obterResumoSaidaCentroCusto(conn, idSaida);
    if (!saida) {
      return res.status(404).json({
        success: false,
        message: 'Saída não encontrada.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        d.ID,
        d.ID_SAIDA,
        d.QUANTIDADE,
        d.OBSERVACAO,
        d.USUARIO_DEVOLUCAO,
        d.DATA_CADASTRO
      FROM SF_ESTOQUE_SAIDA_DEVOLUCAO d
      WHERE d.ID_SAIDA = ?
      ORDER BY d.DATA_CADASTRO DESC, d.ID DESC
      `,
      [idSaida]
    );

    return res.json({
      success: true,
      item: saida,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar devoluções da saída:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar devoluções da saída.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/estoque/centro-custo/saidas/:id/devolucoes', async (req, res) => {
  let conn;

  try {
    const idSaida = Number(req.params.id);
    const quantidade = parseDecimal(req.body.quantidade);
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuario = textolivreTr(req.body.usuario, 150) || 'SISTEMA';

    if (!idSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe o id da saída.'
      });
    }

    if (!(quantidade > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quantidade válida para devolução.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const saida = await obterResumoSaidaCentroCusto(conn, idSaida);
    if (!saida) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Saída não encontrada.'
      });
    }

    const saldoPendente = Number(saida.SALDO_PENDENTE ?? 0);
    if (saldoPendente <= 0) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Esta saída já foi totalmente devolvida.'
      });
    }

    if (quantidade > saldoPendente) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `A devolução não pode exceder o saldo pendente da saída (${saldoPendente}).`
      });
    }

    const [result] = await conn.query(
      `
      INSERT INTO SF_ESTOQUE_SAIDA_DEVOLUCAO
        (
          ID_SAIDA,
          QUANTIDADE,
          OBSERVACAO,
          USUARIO_DEVOLUCAO
        )
      VALUES (?, ?, ?, ?)
      `,
      [
        idSaida,
        quantidade,
        observacao || null,
        usuario
      ]
    );

    const idDevolucao = result.insertId;
    const saldoSaidaAntes = saldoPendente;
    const saldoSaidaDepois = saldoPendente - quantidade;

    await inserirLogDevolucaoSaidaCentroCusto(conn, {
      idDevolucao,
      idSaida,
      acao: 'CRIACAO',
      saldoSaidaAntes,
      quantidadeDevolvida: quantidade,
      saldoSaidaDepois,
      usuario,
      observacao: observacao || 'Devolução de saída registrada.'
    });

    await conn.query(
      `
      UPDATE SF_ESTOQUE_SAIDA_CENTRO_CUSTO
      SET
        USUARIO_ALTERACAO = ?,
        DATA_ALTERACAO = NOW()
      WHERE ID = ?
      `,
      [usuario, idSaida]
    );

    await conn.commit();

    return res.json({
      success: true,
      id: idDevolucao,
      devolucaoParcial: saldoSaidaDepois > 0,
      devolucaoTotal: saldoSaidaDepois <= 0,
      message:
        saldoSaidaDepois > 0
          ? 'Devolução parcial registrada com sucesso.'
          : 'Devolução total registrada com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao registrar devolução da saída:', err);
    try {
      if (conn) await conn.rollback();
    } catch {}
    return res.status(500).json({
      success: false,
      message: 'Erro ao registrar devolução da saída.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/estoque/centro-custo/saidas/:id/historico', async (req, res) => {
  let conn;

  try {
    const idSaida = Number(req.params.id);

    if (!idSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe o id da saída.'
      });
    }

    conn = await pool.getConnection();

    const saida = await obterResumoSaidaCentroCusto(conn, idSaida);
    if (!saida) {
      return res.status(404).json({
        success: false,
        message: 'Saída não encontrada.'
      });
    }

    const [rows] = await conn.query(
      `
      SELECT
        'SAIDA' AS TIPO_EVENTO,
        l.ID,
        l.ID_SAIDA,
        NULL AS ID_DEVOLUCAO,
        l.ACAO,
        l.SALDO_ANTES,
        l.QUANTIDADE_SAIDA AS QUANTIDADE_EVENTO,
        l.SALDO_DEPOIS,
        l.USUARIO,
        l.OBSERVACAO,
        l.DATA_HORA,
        s.FINALIDADE,
        s.USUARIO_SOLICITANTE,
        COALESCE(s.UNIDADE, 'UN') AS UNIDADE
      FROM SF_ESTOQUE_SAIDA_CENTRO_CUSTO_LOG l
      INNER JOIN SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
        ON s.ID = l.ID_SAIDA
      WHERE l.ID_SAIDA = ?

      UNION ALL

      SELECT
        'DEVOLUCAO' AS TIPO_EVENTO,
        dl.ID,
        dl.ID_SAIDA,
        dl.ID_DEVOLUCAO,
        dl.ACAO,
        dl.SALDO_SAIDA_ANTES AS SALDO_ANTES,
        dl.QUANTIDADE_DEVOLVIDA AS QUANTIDADE_EVENTO,
        dl.SALDO_SAIDA_DEPOIS AS SALDO_DEPOIS,
        dl.USUARIO,
        dl.OBSERVACAO,
        dl.DATA_HORA,
        s.FINALIDADE,
        s.USUARIO_SOLICITANTE,
        COALESCE(s.UNIDADE, 'UN') AS UNIDADE
      FROM SF_ESTOQUE_SAIDA_DEVOLUCAO_LOG dl
      INNER JOIN SF_ESTOQUE_SAIDA_CENTRO_CUSTO s
        ON s.ID = dl.ID_SAIDA
      WHERE dl.ID_SAIDA = ?

      ORDER BY DATA_HORA DESC, ID DESC
      `,
      [idSaida, idSaida]
    );

    return res.json({
      success: true,
      item: saida,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar histórico da saída:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar histórico da saída.',
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
        aprovar_reserva_carro,
        aprovar_reserva_carro_gestor,
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
        perfil_acesso,
        monitor_ping
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
        aprovar_reserva_carro,
        aprovar_reserva_carro_gestor,
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
        perfil_acesso,
        monitor_ping
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
      aprovar_reserva_carro: bit(req.body?.aprovar_reserva_carro),
      aprovar_reserva_carro_gestor: bit(req.body?.aprovar_reserva_carro_gestor),
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
      perfil_acesso: bit(req.body?.perfil_acesso),
      monitor_ping: bit(req.body?.monitor_ping)
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
        aprovar_reserva_carro,
        aprovar_reserva_carro_gestor,
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
        perfil_acesso,
        monitor_ping
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      payloadDepois.aprovar_reserva_carro,
      payloadDepois.aprovar_reserva_carro_gestor,
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
      payloadDepois.perfil_acesso,
      payloadDepois.monitor_ping
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
      aprovar_reserva_carro: bit(req.body?.aprovar_reserva_carro),
      aprovar_reserva_carro_gestor: bit(req.body?.aprovar_reserva_carro_gestor),
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
      perfil_acesso: bit(req.body?.perfil_acesso),
      monitor_ping: bit(req.body?.monitor_ping)
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
        aprovar_reserva_carro = ?,
        aprovar_reserva_carro_gestor = ?,
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
        perfil_acesso = ?,
        monitor_ping = ?
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
      depois.aprovar_reserva_carro,
      depois.aprovar_reserva_carro_gestor,
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
      depois.monitor_ping,
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
        COALESCE(p.perfil_acesso, 0) AS perfil_acesso,
        COALESCE(p.reservar_carro, 0) AS reservar_carro,
        COALESCE(p.monitor_ping, 0) AS monitor_ping
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
        perfilacesso: Number(item.perfil_acesso ?? 0),
        reservarcarro: Number(item.reservar_carro ?? 0),
        monitorping: Number(item.monitor_ping ?? 0)
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

// ===== RESERVAR CARRO ===== //
// ========================== //
// ========================== //

function obterStatusQueNaoBloqueiamReserva() {
  return [
    'RECUSADA',
    'DEVOLVIDA',
    'DEVOLVIDO',
    'CANCELADA',
    'CONCLUIDA',
    'CONCLUÍDA'
  ];
}

async function validarConflitoReservaCarro(conn, {
  usuarioSolicitante,
  dataNecessariaMysql,
  previsaoDevolucaoMysql,
  idIgnorar = null
}) {
  const usuarioNormalizado = normalizarTexto(usuarioSolicitante);

  if (!usuarioNormalizado || !dataNecessariaMysql || !previsaoDevolucaoMysql) {
    return null;
  }

  const statusQueNaoBloqueiam = obterStatusQueNaoBloqueiamReserva();

  let sql = `
    SELECT
      id,
      data_necessaria,
      previsao_devolucao,
      status_solicitacao
    FROM SF_RESERVA_CARRO
    WHERE UPPER(TRIM(usuario_solicitante)) = UPPER(TRIM(?))
      AND UPPER(TRIM(status_solicitacao)) NOT IN (${statusQueNaoBloqueiam.map(() => '?').join(', ')})
      AND (
        ? < previsao_devolucao
        AND ? > data_necessaria
      )
  `;

  const params = [
    usuarioNormalizado,
    ...statusQueNaoBloqueiam,
    dataNecessariaMysql,
    previsaoDevolucaoMysql
  ];

  if (idIgnorar) {
    sql += ` AND id <> ?`;
    params.push(Number(idIgnorar));
  }

  sql += ` ORDER BY id DESC LIMIT 1`;

  const [rows] = await conn.query(sql, params);
  return rows?.[0] || null;
}

function datetimeLocalToMysql(v) {
  const s = String(v || '').trim();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);

  if (!m) return null;

  const [, ano, mes, dia, hora, minuto, segundo = '00'] = m;
  return `${ano}-${mes}-${dia} ${hora}:${minuto}:${segundo}`;
}

app.post('/api/reservas-carro', async (req, res) => {
  let conn;

  try {
    const {
      tipo_veiculo,
      data_necessaria,
      previsao_devolucao,
      destinos,
      observacoes,
      urgencia,
      usuario_solicitante,
      termo_aceito,
      foto_aceite_termo,
      termo_versao,
      nome_colaborador,
      matricula_colaborador
    } = req.body || {};

    if (!tipo_veiculo || !data_necessaria || !previsao_devolucao || !urgencia || !usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipo_veiculo, data_necessaria, previsao_devolucao, urgencia e usuario_solicitante.'
      });
    }

    if (!Array.isArray(destinos) || !destinos.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    if (Number(termo_aceito) !== 1) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório aceitar o termo de responsabilidade.'
      });
    }

    if (!normalizarTexto(foto_aceite_termo)) {
      return res.status(400).json({
        success: false,
        message: 'A foto do aceite do termo é obrigatória.'
      });
    }

    const dataNecessariaMysql = datetimeLocalToMysql(data_necessaria);
    const previsaoDevolucaoMysql = datetimeLocalToMysql(previsao_devolucao);

    if (!dataNecessariaMysql || !previsaoDevolucaoMysql) {
      return res.status(400).json({
        success: false,
        message: 'Data necessária ou previsão de devolução inválida.'
      });
    }

    if (previsaoDevolucaoMysql <= dataNecessariaMysql) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const usuarioSolicitanteNormalizado = normalizarTexto(usuario_solicitante);
    const nome_colaboradorNormalizado = normalizarTexto(nome_colaborador || usuario_solicitante);

    const conflito = await validarConflitoReservaCarro(conn, {
      usuarioSolicitante: usuarioSolicitanteNormalizado,
      dataNecessariaMysql,
      previsaoDevolucaoMysql
    });

    if (conflito) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Já existe uma solicitação ativa para este usuário no mesmo período. Reserva conflitante #${conflito.id}.`
      });
    }

    const dadosColaborador = await buscar_dados_colaborador_por_nome(conn, nome_colaboradorNormalizado);

    if (!dadosColaborador) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Colaborador não encontrado na tabela SF_USUARIO.'
      });
    }

    const [insertReserva] = await conn.query(`
      INSERT INTO SF_RESERVA_CARRO (
        tipo_veiculo,
        data_necessaria,
        previsao_devolucao,
        urgencia,
        observacoes,
        usuario_solicitante,
        termo_aceito,
        data_aceite_termo,
        foto_aceite_termo,
        termo_versao,
        nome_colaborador,
        matricula_colaborador,
        cpf_colaborador,
        cnh_colaborador,
        categoria_cnh,
        validade_cnh
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      normalizarTexto(tipo_veiculo).toUpperCase(),
      dataNecessariaMysql,
      previsaoDevolucaoMysql,
      normalizarTexto(urgencia).toUpperCase(),
      observacoes ? normalizarTexto(observacoes) : null,
      usuarioSolicitanteNormalizado,
      1,
      normalizarTexto(foto_aceite_termo),
      normalizarTexto(termo_versao) || '2026-04',
      nome_colaboradorNormalizado,
      normalizarTexto(matricula_colaborador) || null,
      normalizarTexto(dadosColaborador.cpf_colaborador) || null,
      normalizarTexto(dadosColaborador.cnh_colaborador) || null,
      normalizarTexto(dadosColaborador.categoria_cnh) || null,
      dadosColaborador.validade_cnh || null
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


function normalizarCategoriasCNH(valor) {
  if (Array.isArray(valor)) {
    return valor
      .map(v => normalizarTexto(v).toUpperCase())
      .filter(Boolean)
      .join(',');
  }

  return normalizarTexto(valor)
    .split(',')
    .map(v => normalizarTexto(v).toUpperCase())
    .filter(Boolean)
    .join(',');
}

function normalizarDestinosFormulario(valor) {
  if (Array.isArray(valor)) {
    return valor.map(v => Number(v)).filter(Boolean);
  }

  if (typeof valor === 'string' && valor.trim()) {
    return valor
      .split(',')
      .map(v => Number(v.trim()))
      .filter(Boolean);
  }

  return [];
}

function bufferParaDataUrl(file) {
  if (!file?.buffer || !file?.mimetype) return null;
  const base64 = file.buffer.toString('base64');
  return `data:${file.mimetype};base64,${base64}`;
}


app.post('/api/reserva-carro-formulario', uploadMemoria.single('foto_cnh'), async (req, res) => {
  let conn;

  try {
    const {
      nome_completo,
      tipo_veiculo,
      data_necessaria,
      previsao_devolucao,
      observacoes,
      urgencia,
      usuario_solicitante,
      nome_colaborador,
      matricula_colaborador,
      cpf,
      cpf_colaborador,
      numero_cnh,
      cnh_colaborador,
      categoria_cnh,
      validade_cnh,
      origem_solicitacao,
      email,
      telefone,
      termo_aceito,
      foto_aceite_termo,
      termo_versao
    } = req.body || {};

    const destinosRaw = req.body?.['destinos[]'] ?? req.body?.destinos;
    const destinosNormalizados = normalizarDestinosFormulario(destinosRaw);
    const categoriasNormalizadas = normalizarCategoriasCNH(categoria_cnh);

    if (!tipo_veiculo || !data_necessaria || !previsao_devolucao || !urgencia || !usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipo_veiculo, data_necessaria, previsao_devolucao, urgencia e usuario_solicitante.'
      });
    }

    if (!normalizarTexto(nome_completo) && !normalizarTexto(nome_colaborador)) {
      return res.status(400).json({
        success: false,
        message: 'Informe o nome do solicitante.'
      });
    }

    if (!destinosNormalizados.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    if (!categoriasNormalizadas) {
      return res.status(400).json({
        success: false,
        message: 'Selecione ao menos uma categoria da CNH.'
      });
    }

    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'A foto da CNH é obrigatória.'
      });
    }

    if (Number(termo_aceito) !== 1) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório aceitar o termo de responsabilidade.'
      });
    }

    if (!normalizarTexto(foto_aceite_termo)) {
      return res.status(400).json({
        success: false,
        message: 'A foto do aceite do termo é obrigatória.'
      });
    }

    const dataNecessariaMysql = datetimeLocalToMysql(data_necessaria);
    const previsaoDevolucaoMysql = datetimeLocalToMysql(previsao_devolucao);

    if (!dataNecessariaMysql || !previsaoDevolucaoMysql) {
      return res.status(400).json({
        success: false,
        message: 'Data necessária ou previsão de devolução inválida.'
      });
    }

    if (previsaoDevolucaoMysql <= dataNecessariaMysql) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const usuarioSolicitanteNormalizado = normalizarTexto(usuario_solicitante);
    const nomeCompletoNormalizado = normalizarTexto(nome_completo);
    const nomeColaboradorNormalizado = normalizarTexto(nome_colaborador || nome_completo);

    const conflito = await validarConflitoReservaCarro(conn, {
      usuarioSolicitante: usuarioSolicitanteNormalizado,
      dataNecessariaMysql,
      previsaoDevolucaoMysql
    });

    if (conflito) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Já existe uma solicitação ativa para este usuário no mesmo período. Reserva conflitante #${conflito.id}.`
      });
    }

    const [insertReserva] = await conn.query(`
      INSERT INTO SF_RESERVA_CARRO (
        tipo_veiculo,
        data_necessaria,
        previsao_devolucao,
        urgencia,
        observacoes,
        usuario_solicitante,
        termo_aceito,
        data_aceite_termo,
        foto_aceite_termo,
        termo_versao,
        nome_colaborador,
        matricula_colaborador,
        cpf_colaborador,
        cnh_colaborador,
        categoria_cnh,
        validade_cnh,
        origem_solicitacao,
        email,
        telefone
      ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      normalizarTexto(tipo_veiculo).toUpperCase(),
      dataNecessariaMysql,
      previsaoDevolucaoMysql,
      normalizarTexto(urgencia).toUpperCase(),
      normalizarTexto(observacoes) || null,
      usuarioSolicitanteNormalizado,
      1,
      normalizarTexto(foto_aceite_termo),
      normalizarTexto(termo_versao) || '2026-04',
      nomeColaboradorNormalizado || nomeCompletoNormalizado || null,
      normalizarTexto(matricula_colaborador) || null,
      normalizarTexto(cpf_colaborador || cpf) || null,
      normalizarTexto(cnh_colaborador || numero_cnh) || null,
      categoriasNormalizadas,
      normalizarTexto(validade_cnh) || null,
      normalizarTexto(origem_solicitacao) || 'FORMULARIO',
      normalizarTexto(email) || null,
      normalizarTexto(telefone) || null
    ]);

    const reservaId = Number(insertReserva.insertId);

    for (const idDestino of destinosNormalizados) {
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

    console.error('Erro ao salvar reserva de carro via formulário:', err);

    return res.status(500).json({
      success: false,
      message: err?.message || 'Erro ao salvar reserva de carro.'
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

        CASE
          WHEN UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) <> 'PENDENTE' THEN rc.status_solicitacao
          WHEN EXISTS (
            SELECT 1
            FROM SF_ORGANOGRAMA_USUARIO_SETOR ous
            INNER JOIN SF_ORGANOGRAMA_SETOR os
              ON os.ID = ous.ID_SETOR_ORGANOGRAMA
             AND os.STATUS = 1
            INNER JOIN SF_ORGANOGRAMA o
              ON o.id_setor_filho = ous.ID_SETOR_ORGANOGRAMA
             AND o.status = 1
            WHERE ous.ID_USUARIO = u.ID
              AND LOWER(TRIM(COALESCE(ous.PRECISA_APROCAVAO, ''))) = 'sim'
            LIMIT 1
          ) THEN 'PENDENTE GESTOR'
          ELSE 'PENDENTE FROTA'
        END AS status_solicitacao,

        GROUP_CONCAT(lt.nome ORDER BY lt.nome SEPARATOR ' | ') AS destinos

      FROM SF_RESERVA_CARRO rc

      LEFT JOIN SF_RESERVA_CARRO_DESTINO rcd
        ON rcd.reserva_id = rc.id

      LEFT JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id

      LEFT JOIN SF_USUARIO u
        ON UPPER(TRIM(u.NOME)) = UPPER(TRIM(rc.usuario_solicitante))

      GROUP BY
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao,
        u.ID

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
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,

        CASE
          WHEN UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) NOT IN ('PENDENTE', 'PENDENTE GESTOR', 'PENDENTE FROTA')
            THEN rc.status_solicitacao
          WHEN UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) = 'PENDENTE GESTOR'
            THEN 'PENDENTE GESTOR'
          WHEN UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) = 'PENDENTE FROTA'
            THEN 'PENDENTE FROTA'
          WHEN EXISTS (
            SELECT 1
            FROM SF_ORGANOGRAMA_USUARIO_SETOR ous
            INNER JOIN SF_ORGANOGRAMA_SETOR os
              ON os.ID = ous.ID_SETOR_ORGANOGRAMA
             AND os.STATUS = 1
            INNER JOIN SF_ORGANOGRAMA o
              ON o.id_setor_filho = ous.ID_SETOR_ORGANOGRAMA
             AND o.status = 1
            WHERE ous.ID_USUARIO = u.ID
              AND LOWER(TRIM(COALESCE(ous.PRECISA_APROCAVAO, ''))) = 'sim'
            LIMIT 1
          ) THEN 'PENDENTE GESTOR'
          ELSE 'PENDENTE FROTA'
        END AS status_solicitacao,

        rc.motivo_recusa,
        rc.usuario_recusa,
        rc.data_recusa,
        rc.usuario_aprovacao,
        rc.data_aprovacao,
        rc.aprovador_gestor,
        rc.data_aprovacao_gestor,
        rc.veiculo_id,

        rc.termo_aceito,
        rc.data_aceite_termo,
        rc.foto_aceite_termo,
        rc.termo_versao,
        rc.nome_colaborador,
        rc.matricula_colaborador,
        rc.cpf_colaborador,
        rc.cnh_colaborador,
        rc.categoria_cnh,
        rc.validade_cnh,

        rc.checklist_saida,
        rc.km_saida,
        rc.nivel_combustivel_saida,
        rc.foto_frente,
        rc.foto_traseira,
        rc.foto_lateral_esquerda,
        rc.foto_lateral_direita,
        rc.foto_painel,

        rc.checklist_devolucao,
        rc.km_devolucao,
        rc.nivel_combustivel_devolucao,
        rc.observacoes_devolucao,
        rc.foto_devolucao_frente,
        rc.foto_devolucao_traseira,
        rc.foto_devolucao_lateral_esquerda,
        rc.foto_devolucao_lateral_direita,
        rc.foto_devolucao_painel,
        rc.usuario_devolucao,
        rc.data_devolucao,
        rc.usuario_confirmacao_devolucao,
        rc.data_confirmacao_devolucao,

        v.placa AS veiculo_placa,
        v.modelo AS veiculo_modelo,
        v.marca AS veiculo_marca,
        v.cor AS veiculo_cor,
        v.km_atual AS veiculo_km_atual,
        v.status_veiculo AS veiculo_status

      FROM SF_RESERVA_CARRO rc
      LEFT JOIN SF_VEICULOS v
        ON v.id = rc.veiculo_id
      LEFT JOIN SF_USUARIO u
        ON UPPER(TRIM(u.NOME)) = UPPER(TRIM(rc.usuario_solicitante))
      WHERE rc.id = ?
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

    let checklistSaida = {};
    let checklistDevolucao = {};

    try {
      checklistSaida = reserva.checklist_saida
        ? JSON.parse(reserva.checklist_saida)
        : {};
    } catch (_) {
      checklistSaida = {};
    }

    try {
      checklistDevolucao = reserva.checklist_devolucao
        ? JSON.parse(reserva.checklist_devolucao)
        : {};
    } catch (_) {
      checklistDevolucao = {};
    }

    return res.json({
      success: true,
      item: {
        ...reserva,
        checklist_saida: checklistSaida,
        checklist_devolucao: checklistDevolucao,
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

    const statusPermitidos = [
      'PENDENTE',
      'AGUARDANDO_CONFIRMACAO',
      'APROVADA',
      'RECUSADA',
      'CANCELADA',
      'DEVOLVIDA',
      'CONCLUIDA'
    ];
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

app.post('/api/reservas-carro/:id/aprovar-gestor', async (req, res) => {
  let conn;
  try {
    const idReserva = Number(req.params.id);
    const usuarioAprovacaoGestor = String(req.body?.usuarioAprovacaoGestor || '').trim();

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioAprovacaoGestor) {
      return res.status(400).json({
        success: false,
        message: 'Usuário de aprovação do gestor não informado.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rows] = await conn.query(
      `
        SELECT
          rc.id,
          rc.status_solicitacao,
          rc.termo_aceito
        FROM SF_RESERVA_CARRO rc
        WHERE rc.id = ?
        LIMIT 1
      `,
      [idReserva]
    );

    const reserva = rows?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (String(reserva.status_solicitacao || '').trim().toUpperCase() !== 'PENDENTE') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'A reserva não está pendente de aprovação do gestor.'
      });
    }

    if (Number(reserva.termo_aceito || 0) !== 1) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'A reserva não possui termo aceito.'
      });
    }

    await conn.query(
      `
        UPDATE SF_RESERVA_CARRO
        SET
          status_solicitacao = 'PENDENTE FROTA',
          aprovador_gestor = ?,
          data_aprovacao_gestor = NOW()
        WHERE id = ?
      `,
      [usuarioAprovacaoGestor, idReserva]
    );

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva aprovada pelo gestor e enviada para a etapa da frota.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }

    console.error('Erro ao aprovar reserva pelo gestor.', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao aprovar reserva pelo gestor.',
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
    const usuarioId = Number(req.query.usuarioId || 0);

    if (!usuarioSolicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário solicitante.'
      });
    }

    if (!usuarioId) {
      return res.status(400).json({
        success: false,
        message: 'ID do usuário inválido.'
      });
    }

    conn = await pool.getConnection();

    const [permissaoRows] = await conn.query(`
      SELECT
        u.ID AS usuario_id,
        u.NOME AS usuario_nome,
        u.PERFIL AS perfil,
        p.aprovar_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.nome)) = UPPER(TRIM(u.perfil))
      WHERE u.ID = ?
      LIMIT 1
    `, [usuarioId]);

    if (!permissaoRows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const itemPermissao = permissaoRows[0];
    const podeAprovarReservaCarro = Number(itemPermissao.aprovar_reserva_carro) === 1;

    let setoresFilhos = [];
    let setorPaiDoUsuario = null;

    const [vinculoRows] = await conn.query(`
      SELECT
        ous.ID,
        ous.ID_USUARIO,
        ous.ID_SETOR_ORGANOGRAMA,
        ous.PRECISA_APROCAVAO,
        ous.STATUS
      FROM SF_ORGANOGRAMA_USUARIO_SETOR ous
      WHERE ous.ID_USUARIO = ?
        AND ous.STATUS = 1
      ORDER BY ous.ID ASC
      LIMIT 1
    `, [usuarioId]);

    if (vinculoRows.length) {
      setorPaiDoUsuario = Number(vinculoRows[0].ID_SETOR_ORGANOGRAMA || 0);

      if (setorPaiDoUsuario) {
        const [filhosRows] = await conn.query(`
          SELECT DISTINCT o.id_setor_filho
          FROM SF_ORGANOGRAMA o
          INNER JOIN SF_ORGANOGRAMA_SETOR sFilho
            ON sFilho.ID = o.id_setor_filho
           AND sFilho.STATUS = 1
          WHERE o.id_setor_pai = ?
            AND o.status = 1
        `, [setorPaiDoUsuario]);

        setoresFilhos = filhosRows
          .map(item => Number(item.id_setor_filho || 0))
          .filter(Boolean);
      }
    }

    let sql = `
      SELECT
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,

        CASE
          WHEN UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) <> 'PENDENTE' THEN rc.status_solicitacao
          WHEN EXISTS (
            SELECT 1
            FROM SF_ORGANOGRAMA_USUARIO_SETOR ous
            INNER JOIN SF_ORGANOGRAMA_SETOR os
              ON os.ID = ous.ID_SETOR_ORGANOGRAMA
             AND os.STATUS = 1
            INNER JOIN SF_ORGANOGRAMA o
              ON o.id_setor_filho = ous.ID_SETOR_ORGANOGRAMA
             AND o.status = 1
            WHERE ous.ID_USUARIO = uSolicitante.ID
              AND ous.STATUS = 1
              AND LOWER(TRIM(COALESCE(ous.PRECISA_APROCAVAO, ''))) = 'sim'
            LIMIT 1
          ) THEN 'PENDENTE GESTOR'
          ELSE 'PENDENTE FROTA'
        END AS status_solicitacao,

        GROUP_CONCAT(lt.nome ORDER BY lt.nome SEPARATOR ' | ') AS destinos

      FROM SF_RESERVA_CARRO rc

      LEFT JOIN SF_RESERVA_CARRO_DESTINO rcd
        ON rcd.reserva_id = rc.id

      LEFT JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id

      LEFT JOIN SF_USUARIO uSolicitante
        ON UPPER(TRIM(uSolicitante.NOME)) = UPPER(TRIM(rc.usuario_solicitante))
    `;

    const params = [];

    if (!podeAprovarReservaCarro) {
      sql += ` WHERE (UPPER(TRIM(rc.usuario_solicitante)) = UPPER(TRIM(?))`;
      params.push(usuarioSolicitante);

      if (setoresFilhos.length) {
        const placeholders = setoresFilhos.map(() => '?').join(', ');

        sql += `
          OR EXISTS (
            SELECT 1
            FROM SF_USUARIO uFilho
            INNER JOIN SF_ORGANOGRAMA_USUARIO_SETOR ousFilho
              ON ousFilho.ID_USUARIO = uFilho.ID
             AND ousFilho.STATUS = 1
            WHERE UPPER(TRIM(uFilho.NOME)) = UPPER(TRIM(rc.usuario_solicitante))
              AND ousFilho.ID_SETOR_ORGANOGRAMA IN (${placeholders})
          )
        `;

        params.push(...setoresFilhos);
      }

      sql += `)`;
    }

    sql += `
      GROUP BY
        rc.id,
        rc.tipo_veiculo,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.urgencia,
        rc.observacoes,
        rc.usuario_solicitante,
        rc.data_solicitacao,
        rc.status_solicitacao,
        uSolicitante.ID
      ORDER BY rc.id DESC
    `;

    const [rows] = await conn.query(sql, params);

    return res.json({
      success: true,
      items: rows,
      escopo: {
        usuarioId,
        usuarioSolicitante,
        podeAprovarReservaCarro,
        setorPaiDoUsuario,
        setoresFilhos
      }
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

function normalizarTexto(v) {
  return String(v || '').trim();
}

function normalizarStatusReserva(v) {
  return normalizarTexto(v).toUpperCase();
}

async function buscar_dados_colaborador_por_nome(conn, nome_colaborador) {
  const nomeNormalizado = normalizarTexto(nome_colaborador);

  if (!nomeNormalizado) {
    return null;
  }

  const [rows] = await conn.query(`
    SELECT
      u.ID AS usuario_id,
      u.NOME AS nome,
      COALESCE(u.CPF, '') AS cpf_colaborador,
      COALESCE(u.CNH, '') AS cnh_colaborador,
      COALESCE(u.CNH_CATEGORIA, '') AS categoria_cnh,
      u.CNH_VALIDADE AS validade_cnh
    FROM SF_USUARIO u
    WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
    LIMIT 1
  `, [nomeNormalizado]);

  return rows?.[0] || null;
}

app.put('/api/reservas-carro/:id', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const {
      tipo_veiculo,
      data_necessaria,
      previsao_devolucao,
      destinos,
      observacoes,
      urgencia,
      usuario_solicitante,
      termo_aceito,
      foto_aceite_termo,
      termo_versao,
      nome_colaborador,
      matricula_colaborador
    } = req.body || {};

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!tipo_veiculo || !data_necessaria || !previsao_devolucao || !urgencia || !usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipo_veiculo, data_necessaria, previsao_devolucao, urgencia e usuario_solicitante.'
      });
    }

    if (!Array.isArray(destinos) || !destinos.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    if (Number(termo_aceito) !== 1) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório aceitar o termo de responsabilidade.'
      });
    }

    if (!normalizarTexto(foto_aceite_termo)) {
      return res.status(400).json({
        success: false,
        message: 'A foto do aceite do termo é obrigatória.'
      });
    }

    const dataNecessariaMysql = datetimeLocalToMysql(data_necessaria);
    const previsaoDevolucaoMysql = datetimeLocalToMysql(previsao_devolucao);

    if (!dataNecessariaMysql || !previsaoDevolucaoMysql) {
      return res.status(400).json({
        success: false,
        message: 'Data necessária ou previsão de devolução inválida.'
      });
    }

    if (previsaoDevolucaoMysql <= dataNecessariaMysql) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        usuario_solicitante,
        status_solicitacao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (normalizarStatusReserva(reserva.status_solicitacao) !== 'PENDENTE') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas pendentes podem ser editadas.'
      });
    }

    if (normalizarTexto(reserva.usuario_solicitante).toUpperCase() !== normalizarTexto(usuario_solicitante).toUpperCase()) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para editar esta reserva.'
      });
    }

    const usuarioSolicitanteNormalizado = normalizarTexto(usuario_solicitante);
    const nome_colaboradorNormalizado = normalizarTexto(nome_colaborador || usuario_solicitante);

    const conflito = await validarConflitoReservaCarro(conn, {
      usuarioSolicitante: usuarioSolicitanteNormalizado,
      dataNecessariaMysql,
      previsaoDevolucaoMysql,
      idIgnorar: idReserva
    });

    if (conflito) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Já existe outra solicitação ativa para este usuário no mesmo período. Reserva conflitante #${conflito.id}.`
      });
    }

    const dadosColaborador = await buscar_dados_colaborador_por_nome(conn, nome_colaboradorNormalizado);

    if (!dadosColaborador) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Colaborador não encontrado na tabela SF_USUARIO.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        tipo_veiculo = ?,
        data_necessaria = ?,
        previsao_devolucao = ?,
        urgencia = ?,
        observacoes = ?,
        usuario_solicitante = ?,
        termo_aceito = ?,
        data_aceite_termo = NOW(),
        foto_aceite_termo = ?,
        termo_versao = ?,
        nome_colaborador = ?,
        matricula_colaborador = ?,
        cpf_colaborador = ?,
        cnh_colaborador = ?,
        categoria_cnh = ?,
        validade_cnh = ?
      WHERE id = ?
    `, [
      normalizarTexto(tipo_veiculo).toUpperCase(),
      dataNecessariaMysql,
      previsaoDevolucaoMysql,
      normalizarTexto(urgencia).toUpperCase(),
      observacoes ? normalizarTexto(observacoes) : null,
      usuarioSolicitanteNormalizado,
      1,
      normalizarTexto(foto_aceite_termo),
      normalizarTexto(termo_versao) || '2026-04',
      nome_colaboradorNormalizado,
      normalizarTexto(matricula_colaborador) || null,
      normalizarTexto(dadosColaborador.cpf_colaborador) || null,
      normalizarTexto(dadosColaborador.cnh_colaborador) || null,
      normalizarTexto(dadosColaborador.categoria_cnh) || null,
      dadosColaborador.validade_cnh || null,
      idReserva
    ]);

    await conn.query(`
      DELETE FROM SF_RESERVA_CARRO_DESTINO
      WHERE reserva_id = ?
    `, [idReserva]);

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
      `, [idReserva, idDestino]);
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva atualizada com sucesso.'
    });

  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao editar reserva de carro:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao editar reserva de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro/:id/aprovar', async (req, res) => {
  let conn;

  try {

    const fotoFrente = normalizarTexto(req.body?.fotoFrente);
    const fotoTraseira = normalizarTexto(req.body?.fotoTraseira);
    const fotoLateralEsquerda = normalizarTexto(req.body?.fotoLateralEsquerda);
    const fotoLateralDireita = normalizarTexto(req.body?.fotoLateralDireita);
    const fotoPainel = normalizarTexto(req.body?.fotoPainel);

    if (!fotoFrente || !fotoTraseira || !fotoLateralEsquerda || !fotoLateralDireita || !fotoPainel) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório tirar as 5 fotos do veículo no momento da aprovação.'
      });
    }

    const idReserva = Number(req.params.id);
    const usuarioAprovacao = normalizarTexto(
      req.body?.usuarioAprovacao ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );

    const veiculoId = Number(req.body?.veiculoId || 0);
    const kmSaida = req.body?.kmSaida !== undefined && req.body?.kmSaida !== null && req.body?.kmSaida !== ''
      ? Number(req.body.kmSaida)
      : null;
    const nivelCombustivelSaida = normalizarTexto(req.body?.nivelCombustivelSaida);
    const checklistSaida = req.body?.checklistSaida || {};

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioAprovacao) {
      return res.status(400).json({
        success: false,
        message: 'Usuário de aprovação não informado.'
      });
    }

    if (!veiculoId) {
      return res.status(400).json({
        success: false,
        message: 'Selecione um veículo para aprovar a reserva.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        status_solicitacao,
        previsao_devolucao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (normalizarStatusReserva(reserva.status_solicitacao) !== 'PENDENTE FROTA') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas pendentes podem ser aprovadas.'
      });
    }

    const [rowsUsuario] = await conn.query(`
      SELECT
        u.ID,
        u.NOME,
        p.aprovar_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.NOME)) = UPPER(TRIM(u.PERFIL))
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [usuarioAprovacao]);

    const usuarioPermissao = rowsUsuario?.[0];

    if (!usuarioPermissao || Number(usuarioPermissao.aprovar_reserva_carro || 0) !== 1) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para aprovar reservas de carro.'
      });
    }

    const [rowsVeiculo] = await conn.query(`
      SELECT
        id,
        placa,
        modelo,
        status_veiculo,
        ativo,
        km_atual
      FROM SF_VEICULOS
      WHERE id = ?
      LIMIT 1
    `, [veiculoId]);

    const veiculo = rowsVeiculo?.[0];

    if (!veiculo) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Veículo não encontrado.'
      });
    }

    if (Number(veiculo.ativo || 0) !== 1) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está inativo.'
      });
    }

    if (normalizarStatusReserva(veiculo.status_veiculo) === 'MANUTENCAO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está em manutenção.'
      });
    }

    const [rowsConflito] = await conn.query(`
      SELECT
        id,
        previsao_devolucao
      FROM SF_RESERVA_CARRO
      WHERE veiculo_id = ?
        AND id <> ?
        AND UPPER(TRIM(status_solicitacao)) = 'APROVADA'
        AND previsao_devolucao >= NOW()
      LIMIT 1
    `, [veiculoId, idReserva]);

    if (rowsConflito.length) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está em uso e ainda não retornou.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        status_solicitacao = 'APROVADA',
        usuario_aprovacao = ?,
        data_aprovacao = NOW(),
        motivo_recusa = NULL,
        usuario_recusa = NULL,
        data_recusa = NULL,
        veiculo_id = ?,
        checklist_saida = ?,
        km_saida = ?,
        nivel_combustivel_saida = ?,
        foto_frente = ?,
        foto_traseira = ?,
        foto_lateral_esquerda = ?,
        foto_lateral_direita = ?,
        foto_painel = ?
      WHERE id = ?
    `, [
      usuarioAprovacao,
      veiculoId,
      JSON.stringify(checklistSaida || {}),
      kmSaida,
      nivelCombustivelSaida || null,
      fotoFrente,
      fotoTraseira,
      fotoLateralEsquerda,
      fotoLateralDireita,
      fotoPainel,
      idReserva
    ]);


    await conn.query(`
      UPDATE SF_VEICULOS
      SET
        status_veiculo = 'EM_USO',
        km_atual = COALESCE(?, km_atual)
      WHERE id = ?
    `, [kmSaida, veiculoId]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva aprovada com sucesso e veículo associado.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao aprovar reserva:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao aprovar reserva.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro-formulario/:id/aprovar', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const usuarioAprovacao = normalizarTexto(
      req.body?.usuarioAprovacao ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );

    const veiculoId = Number(req.body?.veiculoId || 0);

    const kmSaida = req.body?.kmSaida !== undefined && req.body?.kmSaida !== null && req.body?.kmSaida !== ''
      ? Number(req.body.kmSaida)
      : null;

    const nivelCombustivelSaida = normalizarTexto(req.body?.nivelCombustivelSaida);
    const checklistSaida = req.body?.checklistSaida || {};

    const fotoFrente = normalizarTexto(req.body?.fotoFrente);
    const fotoTraseira = normalizarTexto(req.body?.fotoTraseira);
    const fotoLateralEsquerda = normalizarTexto(req.body?.fotoLateralEsquerda);
    const fotoLateralDireita = normalizarTexto(req.body?.fotoLateralDireita);
    const fotoPainel = normalizarTexto(req.body?.fotoPainel);

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioAprovacao) {
      return res.status(400).json({
        success: false,
        message: 'Usuário de aprovação não informado.'
      });
    }

    if (!veiculoId) {
      return res.status(400).json({
        success: false,
        message: 'Selecione um veículo para aprovar a reserva.'
      });
    }

    if (!fotoFrente || !fotoTraseira || !fotoLateralEsquerda || !fotoLateralDireita || !fotoPainel) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório tirar as 5 fotos do veículo no momento da aprovação.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        status_solicitacao,
        previsao_devolucao,
        origem_solicitacao,
        termo_aceito,
        data_aceite_termo,
        foto_aceite_termo,
        termo_versao,
        nome_colaborador,
        matricula_colaborador,
        cpf_colaborador,
        cnh_colaborador,
        categoria_cnh,
        validade_cnh,
        email,
        telefone,
        usuario_solicitante
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (String(reserva.origem_solicitacao || '').trim().toUpperCase() !== 'FORMULARIO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Esta rota aceita apenas reservas criadas pelo formulário.'
      });
    }


    if (normalizarStatusReserva(reserva.status_solicitacao) !== 'PENDENTE') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas pendentes podem ser aprovadas.'
      });
    }

    if (Number(reserva.termo_aceito || 0) !== 1) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'A reserva não possui aceite de termo válido.'
      });
    }

    const [rowsUsuario] = await conn.query(`
      SELECT
        u.ID,
        u.NOME,
        p.aprovar_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.NOME)) = UPPER(TRIM(u.PERFIL))
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [usuarioAprovacao]);

    const usuarioPermissao = rowsUsuario?.[0];

    if (!usuarioPermissao || Number(usuarioPermissao.aprovar_reserva_carro || 0) !== 1) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para aprovar reservas de carro.'
      });
    }

    const [rowsVeiculo] = await conn.query(`
      SELECT
        id,
        placa,
        modelo,
        status_veiculo,
        ativo,
        km_atual
      FROM SF_VEICULOS
      WHERE id = ?
      LIMIT 1
    `, [veiculoId]);

    const veiculo = rowsVeiculo?.[0];

    if (!veiculo) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Veículo não encontrado.'
      });
    }

    if (Number(veiculo.ativo || 0) !== 1) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está inativo.'
      });
    }

    if (normalizarStatusReserva(veiculo.status_veiculo) === 'MANUTENCAO') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está em manutenção.'
      });
    }

    const [rowsConflito] = await conn.query(`
      SELECT
        id,
        previsao_devolucao
      FROM SF_RESERVA_CARRO
      WHERE veiculo_id = ?
        AND id <> ?
        AND UPPER(TRIM(status_solicitacao)) = 'APROVADA'
        AND previsao_devolucao >= NOW()
      LIMIT 1
    `, [veiculoId, idReserva]);

    if (rowsConflito.length) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo selecionado está em uso e ainda não retornou.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        status_solicitacao = 'APROVADA',
        usuario_aprovacao = ?,
        data_aprovacao = NOW(),
        motivo_recusa = NULL,
        usuario_recusa = NULL,
        data_recusa = NULL,
        veiculo_id = ?,
        checklist_saida = ?,
        km_saida = ?,
        nivel_combustivel_saida = ?,
        foto_frente = ?,
        foto_traseira = ?,
        foto_lateral_esquerda = ?,
        foto_lateral_direita = ?,
        foto_painel = ?
      WHERE id = ?
    `, [
      usuarioAprovacao,
      veiculoId,
      JSON.stringify(checklistSaida || {}),
      kmSaida,
      nivelCombustivelSaida || null,
      fotoFrente,
      fotoTraseira,
      fotoLateralEsquerda,
      fotoLateralDireita,
      fotoPainel,
      idReserva
    ]);

    await conn.query(`
      UPDATE SF_VEICULOS
      SET
        status_veiculo = 'EM_USO',
        km_atual = COALESCE(?, km_atual)
      WHERE id = ?
    `, [kmSaida, veiculoId]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva de formulário aprovada com sucesso e veículo associado.',
      data: {
        id: idReserva,
        origem_solicitacao: reserva.origem_solicitacao,
        usuario_solicitante: reserva.usuario_solicitante,
        nome_colaborador: reserva.nome_colaborador,
        cpf_colaborador: reserva.cpf_colaborador,
        cnh_colaborador: reserva.cnh_colaborador,
        categoria_cnh: reserva.categoria_cnh,
        termo_aceito: reserva.termo_aceito,
        termo_versao: reserva.termo_versao,
        veiculo_id: veiculoId
      }
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao aprovar reserva de formulário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao aprovar reserva de formulário.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro/:id/recusar', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const usuarioRecusa = normalizarTexto(
      req.body?.usuarioRecusa ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );
    const motivoRecusa = normalizarTexto(req.body?.motivoRecusa);

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioRecusa) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário que está recusando a reserva.'
      });
    }

    if (!motivoRecusa) {
      return res.status(400).json({
        success: false,
        message: 'Informe o motivo da recusa.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        status_solicitacao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (normalizarStatusReserva(reserva.status_solicitacao) !== 'PENDENTE') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas pendentes podem ser recusadas.'
      });
    }

    const [usuarioRows] = await conn.query(`
      SELECT
        u.ID,
        u.NOME,
        u.PERFIL,
        p.aprovar_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.nome)) = UPPER(TRIM(u.PERFIL))
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [usuarioRecusa]);

    if (!usuarioRows.length) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Usuário solicitante não encontrado ou sem perfil válido.'
      });
    }

    const usuarioDb = usuarioRows[0];
    const podeAprovarOuRecusar = Number(usuarioDb.aprovar_reserva_carro) === 1;

    if (!podeAprovarOuRecusar) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para recusar esta reserva.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        status_solicitacao = 'RECUSADA',
        motivo_recusa = ?,
        usuario_recusa = ?,
        data_recusa = NOW()
      WHERE id = ?
    `, [motivoRecusa, usuarioRecusa, idReserva]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva recusada com sucesso.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao recusar reserva:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao recusar reserva.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.delete('/api/reservas-carro/:id', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const usuarioExclusao = normalizarTexto(
      req.body?.usuarioExclusao ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioExclusao) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário que está excluindo a reserva.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        usuario_solicitante,
        status_solicitacao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    const [usuarioRows] = await conn.query(`
      SELECT
        u.ID,
        u.NOME,
        u.PERFIL,
        p.excluir_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.NOME)) = UPPER(TRIM(u.PERFIL))
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [usuarioExclusao]);

    if (!usuarioRows.length) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Usuário solicitante não encontrado ou sem perfil válido.'
      });
    }

    const usuarioDb = usuarioRows[0];

    const statusAtual = normalizarStatusReserva(reserva.status_solicitacao);
    const ehCriador =
      normalizarTexto(reserva.usuario_solicitante).toUpperCase() ===
      normalizarTexto(usuarioExclusao).toUpperCase();

    const ehMasterExclusao =
      Number(usuarioDb.excluir_reserva_carro) === 1;

    if (ehCriador) {
      if (statusAtual !== 'PENDENTE') {
        await conn.rollback();
        return res.status(400).json({
          success: false,
          message: 'Você só pode excluir sua própria reserva quando ela estiver pendente.'
        });
      }
    } else {
      if (!ehMasterExclusao) {
        await conn.rollback();
        return res.status(403).json({
          success: false,
          message: 'Você não tem permissão para excluir esta reserva.'
        });
      }

      if (!['PENDENTE', 'RECUSADA', 'CANCELADA'].includes(statusAtual)) {
        await conn.rollback();
        return res.status(400).json({
          success: false,
          message: 'Somente reservas pendentes, recusadas ou canceladas podem ser excluídas.'
        });
      }
    }

    await conn.query(`
      DELETE FROM SF_RESERVA_CARRO_DESTINO
      WHERE reserva_id = ?
    `, [idReserva]);

    await conn.query(`
      DELETE FROM SF_RESERVA_CARRO
      WHERE id = ?
    `, [idReserva]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva excluída com sucesso.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao excluir reserva:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir reserva.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/frota-carros-disponibilidade', async (req, res) => {
  let conn;

  try {
    const data_necessaria = String(req.query.inicio || '').trim();
    const previsao_devolucao = String(req.query.fim || '').trim();
    const tipo_veiculo = String(req.query.tipo_veiculo || '').trim().toUpperCase();

    const data_necessariaMysql = datetimeLocalToMysql(data_necessaria);
    const previsao_devolucaoMysql = datetimeLocalToMysql(previsao_devolucao);

    if (!data_necessariaMysql || !previsao_devolucaoMysql) {
      return res.status(400).json({
        success: false,
        message: 'Informe início e fim válidos.'
      });
    }

    if (previsao_devolucaoMysql <= data_necessariaMysql) {
      return res.status(400).json({
        success: false,
        message: 'A data final deve ser maior que a inicial.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");

    const paramsFrota = [
      previsao_devolucaoMysql,
      data_necessariaMysql
    ];

    let filtroTipoFrota = '';
    if (tipo_veiculo && tipo_veiculo !== 'SEM PREFERÊNCIA') {
      filtroTipoFrota = `
        AND UPPER(TRIM(COALESCE(rc.tipo_veiculo, v.tipo_veiculo, v.status_veiculo, ''))) = ?
      `;
      paramsFrota.push(tipo_veiculo);
    }

    const sqlFrota = `
      SELECT
        v.id,
        v.placa,
        v.modelo,
        v.marca,
        v.cor,
        v.ano,
        v.km_atual,
        v.status_veiculo,
        v.ativo,
        COALESCE(v.tipo_veiculo, '') AS tipo_veiculo,
        rc.id AS reserva_id_atual,
        rc.usuario_solicitante,
        rc.nome_colaborador,
        rc.data_necessaria AS data_reserva,
        rc.previsao_devolucao,
        rc.status_solicitacao,
        CASE
          WHEN COALESCE(v.ativo, 0) <> 1 THEN 'INATIVO'
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '') = 'MANUTENCAO' THEN 'MANUTENCAO'
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '') = 'EM_USO' THEN 'EM_USO'
          WHEN rc.id IS NOT NULL THEN 'EM_USO'
          ELSE 'DISPONIVEL'
        END AS disponibilidade
      FROM SF_VEICULOS v
      LEFT JOIN (
        SELECT
          rc1.id,
          rc1.veiculo_id,
          rc1.usuario_solicitante,
          rc1.nome_colaborador,
          rc1.data_necessaria,
          rc1.previsao_devolucao,
          rc1.status_solicitacao,
          rc1.tipo_veiculo
        FROM SF_RESERVA_CARRO rc1
        INNER JOIN (
          SELECT
            veiculo_id,
            MAX(id) AS max_id
          FROM SF_RESERVA_CARRO
          WHERE REPLACE(UPPER(TRIM(COALESCE(status_solicitacao, ''))), ' ', '') IN ('APROVADA', 'AGUARDANDO_CONFIRMACAO')
            AND veiculo_id IS NOT NULL
          GROUP BY veiculo_id
        ) ult
          ON ult.veiculo_id = rc1.veiculo_id
         AND ult.max_id = rc1.id
      ) rc
        ON rc.veiculo_id = v.id
      WHERE COALESCE(v.ativo, 0) = 1
      ORDER BY
        CASE
          WHEN COALESCE(v.ativo, 0) <> 1 THEN 4
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '') = 'MANUTENCAO' THEN 3
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '') = 'EM_USO' THEN 2
          WHEN rc.id IS NOT NULL THEN 2
          ELSE 1
        END,
        v.modelo ASC,
        v.placa ASC
    `;

    const [rows] = await conn.query(sqlFrota, paramsFrota);

    const paramsSolicitacoes = [];

    let filtroTipoSolicitacoes = '';
    if (tipo_veiculo && tipo_veiculo !== 'SEM PREFERÊNCIA') {
      filtroTipoSolicitacoes = `
        AND UPPER(TRIM(COALESCE(rc.tipo_veiculo, ''))) = ?
      `;
      paramsSolicitacoes.push(tipo_veiculo);
    }

    const sqlSolicitacoesSemVeiculo = `
      SELECT
        rc.id,
        rc.usuario_solicitante,
        rc.nome_colaborador,
        rc.tipo_veiculo,
        rc.status_solicitacao,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.observacoes,
        rc.data_solicitacao
      FROM SF_RESERVA_CARRO rc
      WHERE REPLACE(UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))), ' ', '') NOT IN ('DEVOLVIDA', 'RECUSADA')
        AND rc.veiculo_id IS NULL
        ${filtroTipoSolicitacoes}
      ORDER BY
        rc.data_necessaria ASC,
        rc.id ASC
    `;

    const [rowsSolicitacoesSemVeiculo] = await conn.query(
      sqlSolicitacoesSemVeiculo,
      paramsSolicitacoes
    );

    let destinosPorReserva = {};

    if (rowsSolicitacoesSemVeiculo.length) {
      const idsSolicitacoes = rowsSolicitacoesSemVeiculo.map((item) => item.id);

      const placeholders = idsSolicitacoes.map(() => '?').join(',');

      const sqlDestinos = `
        SELECT
          rcd.reserva_id,
          lt.id AS destino_id,
          lt.nome AS destino_nome
        FROM SF_RESERVA_CARRO_DESTINO rcd
        INNER JOIN SF_LOCAL_TRABALHO lt
          ON lt.id = rcd.local_trabalho_id
        WHERE rcd.reserva_id IN (${placeholders})
        ORDER BY rcd.reserva_id ASC, lt.nome ASC
      `;

      const [rowsDestinos] = await conn.query(sqlDestinos, idsSolicitacoes);

      destinosPorReserva = rowsDestinos.reduce((acc, item) => {
        const reservaId = item.reserva_id;

        if (!acc[reservaId]) {
          acc[reservaId] = [];
        }

        acc[reservaId].push({
          id: item.destino_id,
          nome: item.destino_nome
        });

        return acc;
      }, {});
    }


    return res.json({
      success: true,
      items: rows.map((item) => ({
        id: item.id,
        veiculo_id: item.id,
        placa: item.placa,
        modelo: item.modelo,
        marca: item.marca,
        cor: item.cor,
        ano: item.ano,
        km_atual: item.km_atual,
        status_veiculo: item.status_veiculo,
        ativo: item.ativo,
        tipo_veiculo: item.tipo_veiculo,
        disponibilidade: item.disponibilidade,
        previsao_devolucao: item.previsao_devolucao,
        reserva_id_atual: item.reserva_id_atual,
        status_solicitacao_atual: item.status_solicitacao || null,
        usuario_solicitante: item.usuario_solicitante || null,
        nome_colaborador: item.nome_colaborador || null,
        solicitante_atual: item.nome_colaborador || item.usuario_solicitante || null,
        data_reserva_atual: item.data_reserva || null
      })),
      solicitacoes_sem_veiculo: rowsSolicitacoesSemVeiculo.map((item) => ({
        id: item.id,
        usuario_solicitante: item.usuario_solicitante || null,
        nome_colaborador: item.nome_colaborador || null,
        solicitante: item.nome_colaborador || item.usuario_solicitante || null,
        tipo_veiculo: item.tipo_veiculo || null,
        status_solicitacao: item.status_solicitacao || null,
        data_necessaria: item.data_necessaria || null,
        previsao_devolucao: item.previsao_devolucao || null,
        observacoes: item.observacoes || null,
        data_solicitacao: item.data_solicitacao || null,
        destinos: destinosPorReserva[item.id] || []
      }))
    });
  } catch (err) {
    console.error('Erro ao listar frota por período:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar frota por período.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/frota-carros/:id/reserva-ativa', async (req, res) => {
  let conn;
  try {
    const veiculo_id = Number(req.params.id);


    if (!veiculo_id) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de veículo válido.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");

    const sql = `
      SELECT
        rc.id,
        rc.veiculo_id,
        rc.usuario_solicitante,
        rc.nome_colaborador,
        rc.data_necessaria,
        rc.previsao_devolucao,
        rc.status_solicitacao
      FROM SF_RESERVA_CARRO rc
      WHERE rc.veiculo_id = ?
        AND REPLACE(UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))), ' ', '') IN ('APROVADA', 'AGUARDANDO_CONFIRMACAO')
      ORDER BY rc.previsao_devolucao DESC
      LIMIT 1
    `;

    const params = [veiculo_id];


    const [rowsReserva] = await conn.query(sql, params);


    const reserva = rowsReserva?.[0];


    if (!reserva) {
      return res.status(404).json({
        success: false,
        message: 'Nenhuma reserva ativa encontrada para este veículo.'
      });
    }

    const sqlDestinos = `
      SELECT
        lt.id,
        lt.nome
      FROM SF_RESERVA_CARRO_DESTINO rcd
      INNER JOIN SF_LOCAL_TRABALHO lt
        ON lt.id = rcd.local_trabalho_id
      WHERE rcd.reserva_id = ?
      ORDER BY lt.nome
    `;


    const [destinos] = await conn.query(sqlDestinos, [reserva.id]);


    const responseData = {
      success: true,
      data: {
        reserva_id: reserva.id,
        veiculo_id: reserva.veiculo_id,
        solicitante: reserva.nome_colaborador || reserva.usuario_solicitante,
        usuario_solicitante: reserva.usuario_solicitante,
        data_reserva: reserva.data_necessaria,
        previsao_devolucao: reserva.previsao_devolucao,
        status_solicitacao: reserva.status_solicitacao,
        destinos
      }
    };


    return res.json(responseData);
  } catch (err) {
    console.error('[RESERVA ATIVA] Erro ao buscar reserva ativa do veículo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar reserva ativa do veículo.',
      error: err.message
    });
  } finally {
    if (conn) {
      conn.release();
    }
  }
});

app.get('/api/permissoes/aprovar-reserva-carro/:usuarioId/:status', async (req, res) => {
  let conn;

  try {
    const usuarioId = Number(req.params.usuarioId);
    const statusRecebido = String(req.params.status || '').trim().toUpperCase();

    if (!usuarioId) {
      return res.status(400).json({
        success: false,
        message: 'Informe um usuário válido.'
      });
    }

    if (!statusRecebido) {
      return res.status(400).json({
        success: false,
        message: 'Informe um status válido.'
      });
    }

    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        u.ID AS id_usuario,
        u.NOME AS nome_usuario,
        u.PERFIL AS perfil_usuario,
        p.id AS id_perfil,
        p.nome AS nome_perfil,
        COALESCE(p.aprovar_reserva_carro, 0) AS aprovarreservacarro,
        COALESCE(p.aprovar_reserva_carro_gestor, 0) AS aprovarreservacarrogestao,
        CASE
          WHEN ? = 'PENDENTE GESTOR' THEN COALESCE(p.aprovar_reserva_carro_gestor, 0)
          WHEN ? IN ('PENDENTE FROTA', 'PENDENTE') THEN COALESCE(p.aprovar_reserva_carro, 0)
          ELSE 0
        END AS permissaovalida
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.nome)) = UPPER(TRIM(u.PERFIL))
      WHERE u.ID = ?
      LIMIT 1
    `, [statusRecebido, statusRecebido, usuarioId]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const item = rows[0];

    return res.json({
      success: true,
      item: {
        idusuario: item.id_usuario,
        nomeusuario: item.nome_usuario,
        perfilusuario: item.perfil_usuario,
        idperfil: item.id_perfil,
        nomeperfil: item.nome_perfil,
        statusconsultado: statusRecebido,
        aprovarreservacarro: Number(item.aprovarreservacarro) === 1 ? 1 : 0,
        aprovarreservacarrogestao: Number(item.aprovarreservacarrogestao) === 1 ? 1 : 0,
        permissaovalida: Number(item.permissaovalida) === 1 ? 1 : 0
      }
    });
  } catch (err) {
    console.error('Erro ao validar permissão de aprovar/recusar reserva de carro:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao validar permissão.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro/:id/devolucao', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const usuarioDevolucao = normalizarTexto(
      req.body?.usuarioDevolucao ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );

    const kmDevolucao = req.body?.kmDevolucao !== undefined && req.body?.kmDevolucao !== null && req.body?.kmDevolucao !== ''
      ? Number(req.body.kmDevolucao)
      : null;

    const nivelCombustivelDevolucao = normalizarTexto(req.body?.nivelCombustivelDevolucao);
    const checklistDevolucao = req.body?.checklistDevolucao || {};
    const observacoesDevolucao = normalizarTexto(req.body?.observacoesDevolucao);

    const fotoFrente = normalizarTexto(req.body?.fotoFrente);
    const fotoTraseira = normalizarTexto(req.body?.fotoTraseira);
    const fotoLateralEsquerda = normalizarTexto(req.body?.fotoLateralEsquerda);
    const fotoLateralDireita = normalizarTexto(req.body?.fotoLateralDireita);
    const fotoPainel = normalizarTexto(req.body?.fotoPainel);

    if (!idReserva) {
      return res.status(400).json({ success: false, message: 'Informe um id de reserva válido.' });
    }

    if (!usuarioDevolucao) {
      return res.status(400).json({ success: false, message: 'Usuário da devolução não informado.' });
    }

    if (!fotoFrente || !fotoTraseira || !fotoLateralEsquerda || !fotoLateralDireita || !fotoPainel) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório informar as 5 fotos na devolução.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        usuario_solicitante,
        status_solicitacao,
        veiculo_id
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({ success: false, message: 'Reserva não encontrada.' });
    }

    if (normalizarStatusReserva(reserva.status_solicitacao) !== 'APROVADA') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas aprovadas podem solicitar devolução.'
      });
    }

    const ehCriador =
      normalizarTexto(reserva.usuario_solicitante).toUpperCase() ===
      normalizarTexto(usuarioDevolucao).toUpperCase();

    if (!ehCriador) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para fazer a devolução desta reserva.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        status_solicitacao = 'AGUARDANDO_CONFIRMACAO',
        checklist_devolucao = ?,
        km_devolucao = ?,
        nivel_combustivel_devolucao = ?,
        observacoes_devolucao = ?,
        foto_devolucao_frente = ?,
        foto_devolucao_traseira = ?,
        foto_devolucao_lateral_esquerda = ?,
        foto_devolucao_lateral_direita = ?,
        foto_devolucao_painel = ?,
        usuario_devolucao = ?,
        data_devolucao = NOW()
      WHERE id = ?
    `, [
      JSON.stringify(checklistDevolucao || {}),
      kmDevolucao,
      nivelCombustivelDevolucao || null,
      observacoesDevolucao || null,
      fotoFrente,
      fotoTraseira,
      fotoLateralEsquerda,
      fotoLateralDireita,
      fotoPainel,
      usuarioDevolucao,
      idReserva
    ]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Devolução enviada para confirmação com sucesso.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao solicitar devolução da reserva:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao solicitar devolução da reserva.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/reservas-carro/:id/confirmar-devolucao', async (req, res) => {
  let conn;

  try {
    const idReserva = Number(req.params.id);
    const usuarioConfirmacao = normalizarTexto(
      req.body?.usuarioConfirmacao ||
      req.headers['x-usuario'] ||
      req.headers['x-user']
    );

    if (!idReserva) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!usuarioConfirmacao) {
      return res.status(400).json({
        success: false,
        message: 'Usuário da confirmação não informado.'
      });
    }

    conn = await pool.getConnection();
    await conn.query("SET time_zone = '-03:00'");
    await conn.beginTransaction();

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        status_solicitacao,
        veiculo_id,
        km_devolucao
      FROM SF_RESERVA_CARRO
      WHERE id = ?
      LIMIT 1
    `, [idReserva]);

    const reserva = rowsReserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (![
      'AGUARDANDO_CONFIRMACAO',
      'AGUARDANDO CONFIRMACAO'
    ].includes(normalizarStatusReserva(reserva.status_solicitacao))) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente devoluções aguardando confirmação podem ser confirmadas.'
      });
    }

    const [usuarioRows] = await conn.query(`
      SELECT
        u.ID,
        u.NOME,
        p.aprovar_reserva_carro
      FROM SF_USUARIO u
      LEFT JOIN SF_PERFIL p
        ON UPPER(TRIM(p.NOME)) = UPPER(TRIM(u.PERFIL))
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [usuarioConfirmacao]);

    const usuarioDb = usuarioRows?.[0];

    if (!usuarioDb || Number(usuarioDb.aprovar_reserva_carro || 0) !== 1) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para confirmar devoluções.'
      });
    }

    await conn.query(`
      UPDATE SF_RESERVA_CARRO
      SET
        status_solicitacao = 'DEVOLVIDA',
        usuario_confirmacao_devolucao = ?,
        data_confirmacao_devolucao = NOW()
      WHERE id = ?
    `, [usuarioConfirmacao, idReserva]);

    if (Number(reserva.veiculo_id || 0)) {
      await conn.query(`
        UPDATE SF_VEICULOS
        SET
          status_veiculo = 'DISPONIVEL',
          km_atual = COALESCE(?, km_atual)
        WHERE id = ?
      `, [reserva.km_devolucao, reserva.veiculo_id]);
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Devolução confirmada com sucesso.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao confirmar devolução:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao confirmar devolução.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

function normalizar_texto(valor) {
  return String(valor ?? '').trim();
}

function normalizar_texto_upper(valor) {
  return normalizar_texto(valor).toUpperCase();
}

function normalizar_status_reserva(valor) {
  return normalizar_texto_upper(valor);
}

function obter_status_que_nao_bloqueiam_reserva() {
  return ['RECUSADA', 'DEVOLVIDA', 'DEVOLVIDO', 'CANCELADA', 'CONCLUIDA', 'CONCLUIDO'];
}

function datetime_local_para_mysql(valor) {
  const texto = String(valor ?? '').trim();
  const match = texto.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);

  if (!match) return null;

  const [, ano, mes, dia, hora, minuto, segundo = '00'] = match;
  return `${ano}-${mes}-${dia} ${hora}:${minuto}:${segundo}`;
}

async function validar_conflito_reserva_carro(
  conn,
  usuario_solicitante,
  data_necessaria_mysql,
  previsao_devolucao_mysql,
  id_ignorar = null
) {
  const usuario_normalizado = normalizar_texto(usuario_solicitante);

  if (!usuario_normalizado || !data_necessaria_mysql || !previsao_devolucao_mysql) {
    return null;
  }

  const status_que_nao_bloqueiam = obter_status_que_nao_bloqueiam_reserva();

  let sql = `
    SELECT
      id,
      data_necessaria,
      previsao_devolucao,
      status_solicitacao
    FROM SF_RESERVA_CARRO
    WHERE UPPER(TRIM(usuario_solicitante)) = UPPER(TRIM(?))
      AND UPPER(TRIM(status_solicitacao)) NOT IN (${status_que_nao_bloqueiam.map(() => '?').join(', ')})
      AND ? < previsao_devolucao
      AND ? > data_necessaria
  `;

  const params = [
    usuario_normalizado,
    ...status_que_nao_bloqueiam,
    data_necessaria_mysql,
    previsao_devolucao_mysql
  ];

  if (id_ignorar) {
    sql += ` AND id <> ? `;
    params.push(Number(id_ignorar));
  }

  sql += ` ORDER BY id DESC LIMIT 1 `;

  const rows = await conn.query(sql, params);
  return rows?.[0] || null;
}

async function buscar_dados_condutor_por_usuario(conn, usuario_solicitante) {
  const usuario_normalizado = normalizar_texto(usuario_solicitante);

  if (!usuario_normalizado) return null;

  const [rows] = await conn.query(
    `
      SELECT
        u.ID AS usuario_id,
        u.NOME AS nome
      FROM SF_USUARIO u
      WHERE UPPER(TRIM(u.NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `,
    [usuario_normalizado]
  );

  const item = rows?.[0] || null;
  if (!item) return null;

  return {
    usuario_id: item.usuario_id,
    nome: item.nome || '',
    matricula: '',
    cpf: '',
    cnh: '',
    categoria_cnh: '',
    validade_cnh: null
  };
}

async function contar_veiculos_disponiveis_no_periodo(conn, {
  tipo_veiculo,
  data_necessaria_mysql,
  previsao_devolucao_mysql
}) {
  const tipo_veiculo_normalizado = normalizar_texto_upper(tipo_veiculo);
  const params = [data_necessaria_mysql, previsao_devolucao_mysql];

  let sql = `
    SELECT COUNT(*) AS total
    FROM SF_VEICULOS v
    WHERE COALESCE(v.ativo, 0) = 1
      AND UPPER(TRIM(COALESCE(v.status_veiculo, 'DISPONIVEL'))) <> 'MANUTENCAO'
  `;

  if (
    tipo_veiculo_normalizado &&
    tipo_veiculo_normalizado !== 'SEM PREFERÊNCIA' &&
    tipo_veiculo_normalizado !== 'SEM PREFERENCIA'
  ) {
    sql += ` AND UPPER(TRIM(COALESCE(v.tipo_veiculo, ''))) = ? `;
    params.push(tipo_veiculo_normalizado);
  }

  sql += `
      AND NOT EXISTS (
        SELECT 1
        FROM SF_RESERVA_CARRO rc
        WHERE rc.veiculo_id = v.id
          AND UPPER(TRIM(COALESCE(rc.status_solicitacao, ''))) = 'APROVADA'
          AND ? < rc.previsao_devolucao
          AND ? > rc.data_necessaria
      )
  `;

  params.push(data_necessaria_mysql, previsao_devolucao_mysql);

  const rows = await conn.query(sql, params);
  return Number(rows?.[0]?.total || 0);
}

app.get('/api/reservas-carro/solicitante/:usuario_solicitante', async (req, res) => {
  let conn;

  try {
    const usuario_solicitante = normalizar_texto(req.params.usuario_solicitante);

    if (!usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe o usuário solicitante.'
      });
    }

    conn = await pool.getConnection();

    const item = await buscar_dados_condutor_por_usuario(conn, usuario_solicitante);

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Dados do solicitante não encontrados.'
      });
    }

    return res.json({
      success: true,
      item: {
        usuario_id: item.usuario_id,
        nome: item.nome,
        matricula: item.matricula || '',
        cpf: item.cpf || '',
        cnh: item.cnh || '',
        categoria_cnh: item.categoria_cnh || '',
        validade_cnh: item.validade_cnh || null
      }
    });
  } catch (err) {
    console.error('Erro ao buscar dados do solicitante.', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar dados do solicitante.',
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
      tipo_veiculo,
      data_necessaria,
      previsao_devolucao,
      destinos,
      observacoes,
      urgencia,
      usuario_solicitante,
      termo_aceito,
      foto_aceite_termo,
      termo_versao,
      nome_colaborador,
      matricula_colaborador,
      cpf_colaborador,
      cnh_colaborador,
      categoria_cnh,
      validade_cnh
    } = req.body || {};

    if (!tipo_veiculo || !data_necessaria || !previsao_devolucao || !urgencia || !usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipo_veiculo, data_necessaria, previsao_devolucao, urgencia e usuario_solicitante.'
      });
    }

    if (!Array.isArray(destinos) || !destinos.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    const data_necessaria_mysql = datetime_local_para_mysql(data_necessaria);
    const previsao_devolucao_mysql = datetime_local_para_mysql(previsao_devolucao);

    if (!data_necessaria_mysql || !previsao_devolucao_mysql) {
      return res.status(400).json({
        success: false,
        message: 'Data necessária ou previsão de devolução inválida.'
      });
    }

    if (previsao_devolucao_mysql <= data_necessaria_mysql) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    if (Number(termo_aceito) !== 1) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório aceitar o termo de responsabilidade.'
      });
    }

    if (!normalizar_texto(foto_aceite_termo)) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório enviar a foto de aceite do termo.'
      });
    }

    conn = await pool.getConnection();
    await conn.query(`SET time_zone = '-03:00'`);
    await conn.beginTransaction();

    const usuario_solicitante_normalizado = normalizar_texto(usuario_solicitante);

    const conflito = await validar_conflito_reserva_carro(
      conn,
      usuario_solicitante_normalizado,
      data_necessaria_mysql,
      previsao_devolucao_mysql
    );

    if (conflito) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Já existe uma solicitação ativa para este usuário no mesmo período. Reserva conflitante #${conflito.id}.`
      });
    }

    const total_disponiveis = await contar_veiculos_disponiveis_no_periodo(conn, {
      tipo_veiculo,
      data_necessaria_mysql,
      previsao_devolucao_mysql
    });

    if (total_disponiveis <= 0) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        sem_disponibilidade: true,
        message: 'Não há veículo disponível para o período solicitado. Ajuste a data/período ou fale com a logística.'
      });
    }

    const result = await conn.query(
      `
        INSERT INTO SF_RESERVA_CARRO (
          tipo_veiculo,
          data_necessaria,
          previsao_devolucao,
          urgencia,
          observacoes,
          usuario_solicitante,
          termo_aceito,
          data_aceite_termo,
          foto_aceite_termo,
          termo_versao,
          nome_colaborador,
          matricula_colaborador,
          cpf_colaborador,
          cnh_colaborador,
          categoria_cnh,
          validade_cnh
        ) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        normalizar_texto_upper(tipo_veiculo),
        data_necessaria_mysql,
        previsao_devolucao_mysql,
        normalizar_texto_upper(urgencia),
        normalizar_texto(observacoes) || null,
        usuario_solicitante_normalizado,
        1,
        normalizar_texto(foto_aceite_termo),
        normalizar_texto(termo_versao) || '2026-04',
        normalizar_texto(nome_colaborador) || usuario_solicitante_normalizado,
        normalizar_texto(matricula_colaborador) || null,
        normalizar_texto(cpf_colaborador) || null,
        normalizar_texto(cnh_colaborador) || null,
        normalizar_texto(categoria_cnh) || null,
        normalizar_texto(validade_cnh) || null
      ]
    );

    const reserva_id = Number(result.insertId || 0);

    for (const id_destino_raw of destinos) {
      const local_trabalho_id = Number(id_destino_raw);

      if (!local_trabalho_id) {
        throw new Error('Foi encontrado um destino inválido na solicitação.');
      }

      await conn.query(
        `
          INSERT INTO SF_RESERVA_CARRO_DESTINO (
            reserva_id,
            local_trabalho_id
          ) VALUES (?, ?)
        `,
        [reserva_id, local_trabalho_id]
      );
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Solicitação de reserva de carro salva com sucesso.',
      reserva_id
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }

    console.error('Erro ao salvar reserva de carro.', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar reserva de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/reservas-carro/:id', async (req, res) => {
  let conn;

  try {
    const reserva_id = Number(req.params.id);

    const {
      tipo_veiculo,
      data_necessaria,
      previsao_devolucao,
      destinos,
      observacoes,
      urgencia,
      usuario_solicitante,
      termo_aceito,
      foto_aceite_termo,
      termo_versao,
      nome_colaborador,
      matricula_colaborador,
      cpf_colaborador,
      cnh_colaborador,
      categoria_cnh,
      validade_cnh
    } = req.body || {};

    if (!reserva_id) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de reserva válido.'
      });
    }

    if (!tipo_veiculo || !data_necessaria || !previsao_devolucao || !urgencia || !usuario_solicitante) {
      return res.status(400).json({
        success: false,
        message: 'Informe tipo_veiculo, data_necessaria, previsao_devolucao, urgencia e usuario_solicitante.'
      });
    }

    if (!Array.isArray(destinos) || !destinos.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione pelo menos um destino.'
      });
    }

    const data_necessaria_mysql = datetime_local_para_mysql(data_necessaria);
    const previsao_devolucao_mysql = datetime_local_para_mysql(previsao_devolucao);

    if (!data_necessaria_mysql || !previsao_devolucao_mysql) {
      return res.status(400).json({
        success: false,
        message: 'Data necessária ou previsão de devolução inválida.'
      });
    }

    if (previsao_devolucao_mysql <= data_necessaria_mysql) {
      return res.status(400).json({
        success: false,
        message: 'A previsão de devolução deve ser maior que a data necessária.'
      });
    }

    if (Number(termo_aceito) !== 1) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório aceitar o termo de responsabilidade.'
      });
    }

    if (!normalizar_texto(foto_aceite_termo)) {
      return res.status(400).json({
        success: false,
        message: 'É obrigatório enviar a foto de aceite do termo.'
      });
    }

    conn = await pool.getConnection();
    await conn.query(`SET time_zone = '-03:00'`);
    await conn.beginTransaction();

    const rows_reserva = await conn.query(
      `
        SELECT
          id,
          usuario_solicitante,
          status_solicitacao
        FROM SF_RESERVA_CARRO
        WHERE id = ?
        LIMIT 1
      `,
      [reserva_id]
    );

    const reserva = rows_reserva?.[0];

    if (!reserva) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Reserva não encontrada.'
      });
    }

    if (normalizar_status_reserva(reserva.status_solicitacao) !== 'PENDENTE') {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Somente reservas pendentes podem ser editadas.'
      });
    }

    if (normalizar_texto_upper(reserva.usuario_solicitante) !== normalizar_texto_upper(usuario_solicitante)) {
      await conn.rollback();
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para editar esta reserva.'
      });
    }

    const usuario_solicitante_normalizado = normalizar_texto(usuario_solicitante);

    const conflito = await validar_conflito_reserva_carro(
      conn,
      usuario_solicitante_normalizado,
      data_necessaria_mysql,
      previsao_devolucao_mysql,
      reserva_id
    );

    if (conflito) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: `Já existe outra solicitação ativa para este usuário no mesmo período. Reserva conflitante #${conflito.id}.`
      });
    }

    const total_disponiveis = await contar_veiculos_disponiveis_no_periodo(conn, {
      tipo_veiculo,
      data_necessaria_mysql,
      previsao_devolucao_mysql
    });

    if (total_disponiveis <= 0) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        sem_disponibilidade: true,
        message: 'Não há veículo disponível para o período solicitado. Ajuste a data/período ou fale com a logística.'
      });
    }

    await conn.query(
      `
        UPDATE SF_RESERVA_CARRO
        SET
          tipo_veiculo = ?,
          data_necessaria = ?,
          previsao_devolucao = ?,
          urgencia = ?,
          observacoes = ?,
          usuario_solicitante = ?,
          termo_aceito = 1,
          data_aceite_termo = NOW(),
          foto_aceite_termo = ?,
          termo_versao = ?,
          nome_colaborador = ?,
          matricula_colaborador = ?,
          cpf_colaborador = ?,
          cnh_colaborador = ?,
          categoria_cnh = ?,
          validade_cnh = ?
        WHERE id = ?
      `,
      [
        normalizar_texto_upper(tipo_veiculo),
        data_necessaria_mysql,
        previsao_devolucao_mysql,
        normalizar_texto_upper(urgencia),
        normalizar_texto(observacoes) || null,
        usuario_solicitante_normalizado,
        normalizar_texto(foto_aceite_termo),
        normalizar_texto(termo_versao) || '2026-04',
        normalizar_texto(nome_colaborador) || usuario_solicitante_normalizado,
        normalizar_texto(matricula_colaborador) || null,
        normalizar_texto(cpf_colaborador) || null,
        normalizar_texto(cnh_colaborador) || null,
        normalizar_texto(categoria_cnh) || null,
        normalizar_texto(validade_cnh) || null,
        reserva_id
      ]
    );

    await conn.query(`DELETE FROM SF_RESERVA_CARRO_DESTINO WHERE reserva_id = ?`, [reserva_id]);

    for (const id_destino_raw of destinos) {
      const local_trabalho_id = Number(id_destino_raw);

      if (!local_trabalho_id) {
        throw new Error('Foi encontrado um destino inválido na solicitação.');
      }

      await conn.query(
        `
          INSERT INTO SF_RESERVA_CARRO_DESTINO (
            reserva_id,
            local_trabalho_id
          ) VALUES (?, ?)
        `,
        [reserva_id, local_trabalho_id]
      );
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Reserva atualizada com sucesso.',
      reserva_id
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch {}
    }

    console.error('Erro ao editar reserva de carro.', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao editar reserva de carro.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});



// Cadastro de Veiculos e Utilização de Veículos

app.get('/api/reservas-carro/:id/veiculos-disponiveis', async (req, res) => {
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
    await conn.query("SET time_zone = '-03:00'");

    const [rowsReserva] = await conn.query(`
      SELECT
        id,
        tipo_veiculo,
        data_necessaria,
        previsao_devolucao,
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

    const [rows] = await conn.query(`
      SELECT
        v.id,
        v.placa,
        v.modelo,
        v.marca,
        v.cor,
        v.ano,
        v.km_atual,
        v.status_veiculo,
        v.ativo,
        CASE
          WHEN COALESCE(v.ativo, 0) <> 1 THEN 'INATIVO'
          WHEN UPPER(TRIM(COALESCE(v.status_veiculo, ''))) = 'MANUTENCAO' THEN 'MANUTENCAO'
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '_') IN ('EM_USO', 'EMUSO') THEN 'EM_USO'
          WHEN EXISTS (
            SELECT 1
            FROM SF_RESERVA_CARRO rc
            WHERE rc.veiculo_id = v.id
              AND rc.id <> ?
              AND UPPER(TRIM(rc.status_solicitacao)) = 'APROVADA'
              AND rc.previsao_devolucao >= NOW()
          ) THEN 'EM_USO'
          ELSE 'DISPONIVEL'
        END AS disponibilidade,
        (
          SELECT rc.previsao_devolucao
          FROM SF_RESERVA_CARRO rc
          WHERE rc.veiculo_id = v.id
            AND rc.id <> ?
            AND UPPER(TRIM(rc.status_solicitacao)) = 'APROVADA'
            AND rc.previsao_devolucao >= NOW()
          ORDER BY rc.previsao_devolucao ASC
          LIMIT 1
        ) AS previsao_retorno
      FROM SF_VEICULOS v
      WHERE COALESCE(v.ativo, 0) = 1
      ORDER BY
        CASE
          WHEN UPPER(TRIM(COALESCE(v.status_veiculo, ''))) = 'MANUTENCAO' THEN 3
          WHEN REPLACE(UPPER(TRIM(COALESCE(v.status_veiculo, ''))), ' ', '_') IN ('EM_USO', 'EMUSO') THEN 2
          WHEN EXISTS (
            SELECT 1
            FROM SF_RESERVA_CARRO rc
            WHERE rc.veiculo_id = v.id
              AND rc.id <> ?
              AND UPPER(TRIM(rc.status_solicitacao)) = 'APROVADA'
              AND rc.previsao_devolucao >= NOW()
          ) THEN 2
          ELSE 1
        END,
        v.modelo,
        v.placa
    `, [idReserva, idReserva, idReserva]);

    return res.json({
      success: true,
      reserva: {
        id: reserva.id,
        tipoVeiculo: reserva.tipo_veiculo,
        dataNecessaria: reserva.data_necessaria,
        previsaoDevolucao: reserva.previsao_devolucao,
        statusSolicitacao: reserva.status_solicitacao
      },
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar veículos disponíveis:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar veículos disponíveis.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

function normalizarTextoVeiculos(value) {
  return String(value ?? '').trim();
}

function normalizarTextoVeiculosUpper(value) {
  return normalizarTextoVeiculos(value).toUpperCase();
}

function normalizarStatusVeiculo(value) {
  const status = normalizarTextoVeiculosUpper(value)
    .replace(/\s+/g, '_')
    .replace(/[^A-Z_]/g, '');

  if (status === 'EMUSO') return 'EM_USO';
  if (status === 'EM_USO') return 'EM_USO';
  if (status === 'MANUTENCAO') return 'MANUTENCAO';
  if (status === 'DISPONIVEL') return 'DISPONIVEL';

  return status || 'DISPONIVEL';
}

app.get('/api/veiculos', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        id,
        placa,
        modelo,
        marca,
        cor,
        ano,
        km_atual,
        status_veiculo,
        ativo,
        observacoes,
        created_at,
        updated_at
      FROM SF_VEICULOS
      ORDER BY ativo DESC, modelo ASC, placa ASC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar veículos:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar veículos.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/veiculos/:id', async (req, res) => {
  let conn;

  try {
    const idVeiculo = Number(req.params.id);

    if (!idVeiculo) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de veículo válido.'
      });
    }

    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        id,
        placa,
        modelo,
        marca,
        cor,
        ano,
        km_atual,
        status_veiculo,
        ativo,
        observacoes,
        created_at,
        updated_at
      FROM SF_VEICULOS
      WHERE id = ?
      LIMIT 1
    `, [idVeiculo]);

    const item = rows?.[0];

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Veículo não encontrado.'
      });
    }

    return res.json({
      success: true,
      item
    });
  } catch (err) {
    console.error('Erro ao buscar veículo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar veículo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/veiculos', async (req, res) => {
  let conn;

  try {
    const placa = normalizarTextoVeiculosUpper(req.body?.placa).replace(/[^A-Z0-9]/g, '');
    const modelo = normalizarTextoVeiculos(req.body?.modelo);
    const marca = normalizarTextoVeiculos(req.body?.marca);
    const cor = normalizarTextoVeiculos(req.body?.cor);
    const ano = req.body?.ano !== undefined && req.body?.ano !== null && req.body?.ano !== ''
      ? Number(req.body.ano)
      : null;
    const kmAtual = req.body?.kmAtual !== undefined && req.body?.kmAtual !== null && req.body?.kmAtual !== ''
      ? Number(req.body.kmAtual)
      : null;
    const statusVeiculo = normalizarStatusVeiculo(req.body?.statusVeiculo);
    const ativo = Number(req.body?.ativo ?? 1) === 1 ? 1 : 0;
    const observacoes = normalizarTextoVeiculos(req.body?.observacoes);

    if (!placa) {
      return res.status(400).json({
        success: false,
        message: 'Informe a placa do veículo.'
      });
    }

    if (!modelo) {
      return res.status(400).json({
        success: false,
        message: 'Informe o modelo do veículo.'
      });
    }

    if (ano !== null && (!Number.isInteger(ano) || ano < 1900 || ano > 2100)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um ano válido.'
      });
    }

    if (kmAtual !== null && (!Number.isFinite(kmAtual) || kmAtual < 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quilometragem válida.'
      });
    }

    if (!['DISPONIVEL', 'EM_USO', 'MANUTENCAO'].includes(statusVeiculo)) {
      return res.status(400).json({
        success: false,
        message: 'Status do veículo inválido.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsPlaca] = await conn.query(`
      SELECT id
      FROM SF_VEICULOS
      WHERE UPPER(REPLACE(TRIM(placa), '-', '')) = ?
      LIMIT 1
    `, [placa]);

    if (rowsPlaca.length) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Já existe um veículo cadastrado com esta placa.'
      });
    }

    const [result] = await conn.query(`
      INSERT INTO SF_VEICULOS (
        placa,
        modelo,
        marca,
        cor,
        ano,
        km_atual,
        status_veiculo,
        ativo,
        observacoes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      placa,
      modelo,
      marca || null,
      cor || null,
      ano,
      kmAtual,
      statusVeiculo,
      ativo,
      observacoes || null
    ]);

    await conn.commit();

    return res.status(201).json({
      success: true,
      message: 'Veículo cadastrado com sucesso.',
      id: result.insertId
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao cadastrar veículo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar veículo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/veiculos/:id', async (req, res) => {
  let conn;

  try {
    const idVeiculo = Number(req.params.id);
    const placa = normalizarTextoVeiculosUpper(req.body?.placa).replace(/[^A-Z0-9]/g, '');
    const modelo = normalizarTextoVeiculos(req.body?.modelo);
    const marca = normalizarTextoVeiculos(req.body?.marca);
    const cor = normalizarTextoVeiculos(req.body?.cor);
    const ano = req.body?.ano !== undefined && req.body?.ano !== null && req.body?.ano !== ''
      ? Number(req.body.ano)
      : null;
    const kmAtual = req.body?.kmAtual !== undefined && req.body?.kmAtual !== null && req.body?.kmAtual !== ''
      ? Number(req.body.kmAtual)
      : null;
    const statusVeiculo = normalizarStatusVeiculo(req.body?.statusVeiculo);
    const ativo = Number(req.body?.ativo ?? 1) === 1 ? 1 : 0;
    const observacoes = normalizarTextoVeiculos(req.body?.observacoes);

    if (!idVeiculo) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de veículo válido.'
      });
    }

    if (!placa) {
      return res.status(400).json({
        success: false,
        message: 'Informe a placa do veículo.'
      });
    }

    if (!modelo) {
      return res.status(400).json({
        success: false,
        message: 'Informe o modelo do veículo.'
      });
    }

    if (ano !== null && (!Number.isInteger(ano) || ano < 1900 || ano > 2100)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um ano válido.'
      });
    }

    if (kmAtual !== null && (!Number.isFinite(kmAtual) || kmAtual < 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe uma quilometragem válida.'
      });
    }

    if (!['DISPONIVEL', 'EM_USO', 'MANUTENCAO'].includes(statusVeiculo)) {
      return res.status(400).json({
        success: false,
        message: 'Status do veículo inválido.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsExistente] = await conn.query(`
      SELECT id
      FROM SF_VEICULOS
      WHERE id = ?
      LIMIT 1
    `, [idVeiculo]);

    if (!rowsExistente.length) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Veículo não encontrado.'
      });
    }

    const [rowsPlaca] = await conn.query(`
      SELECT id
      FROM SF_VEICULOS
      WHERE UPPER(REPLACE(TRIM(placa), '-', '')) = ?
        AND id <> ?
      LIMIT 1
    `, [placa, idVeiculo]);

    if (rowsPlaca.length) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'Já existe outro veículo cadastrado com esta placa.'
      });
    }

    await conn.query(`
      UPDATE SF_VEICULOS
      SET
        placa = ?,
        modelo = ?,
        marca = ?,
        cor = ?,
        ano = ?,
        km_atual = ?,
        status_veiculo = ?,
        ativo = ?,
        observacoes = ?
      WHERE id = ?
    `, [
      placa,
      modelo,
      marca || null,
      cor || null,
      ano,
      kmAtual,
      statusVeiculo,
      ativo,
      observacoes || null,
      idVeiculo
    ]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Veículo atualizado com sucesso.'
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao atualizar veículo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar veículo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.delete('/api/veiculos/:id', async (req, res) => {
  let conn;

  try {
    const idVeiculo = Number(req.params.id);

    if (!idVeiculo) {
      return res.status(400).json({
        success: false,
        message: 'Informe um id de veículo válido.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [rowsVeiculo] = await conn.query(`
      SELECT
        id,
        modelo,
        placa,
        status_veiculo
      FROM SF_VEICULOS
      WHERE id = ?
      LIMIT 1
    `, [idVeiculo]);

    const veiculo = rowsVeiculo?.[0];

    if (!veiculo) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Veículo não encontrado.'
      });
    }

    const [rowsReservaAberta] = await conn.query(`
      SELECT id
      FROM SF_RESERVA_CARRO
      WHERE veiculo_id = ?
        AND UPPER(TRIM(status_solicitacao)) = 'APROVADA'
        AND previsao_devolucao >= NOW()
      LIMIT 1
    `, [idVeiculo]);

    if (rowsReservaAberta.length) {
      await conn.rollback();
      return res.status(400).json({
        success: false,
        message: 'O veículo possui reserva aprovada em aberto e não pode ser excluído.'
      });
    }

    await conn.query(`
      DELETE FROM SF_VEICULOS
      WHERE id = ?
    `, [idVeiculo]);

    await conn.commit();

    return res.json({
      success: true,
      message: 'Veículo excluído com sucesso.',
      item: {
        id: veiculo.id,
        modelo: veiculo.modelo,
        placa: veiculo.placa
      }
    });
  } catch (err) {
    if (conn) {
      try { await conn.rollback(); } catch (_) {}
    }

    console.error('Erro ao excluir veículo:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir veículo.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});


// =========================
// CADASTRO ORGANOGRAMA
// =========================

// Listar locais de trabalho para o organograma
app.get('/api/local-trabalho', async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();

    const [result] = await conn.query(`
      SELECT
        ID AS id,
        NOME AS nome,
        ENDERECO AS endereco,
        TELEFONE AS telefone
      FROM SF_LOCAL_TRABALHO
      ORDER BY NOME ASC
    `);

    const rows = Array.isArray(result?.[0]) ? result[0] : result;

    return res.json({
      success: true,
      items: rows
    });
  } catch (error) {
    console.error('Erro ao listar locais de trabalho:', error);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar locais de trabalho.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// Listar vínculos do organograma
app.get('/api/organograma', async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();

    const { id_local_trabalho, status } = req.query;
    const filtros = [];
    const params = [];

    if (String(id_local_trabalho ?? '').trim() !== '') {
      filtros.push('o.id_local_trabalho = ?');
      params.push(Number(id_local_trabalho));
    }

    if (String(status ?? '').trim() !== '') {
      filtros.push('o.status = ?');
      params.push(Number(status) === 1 ? 1 : 0);
    }

    const where = filtros.length ? `WHERE ${filtros.join(' AND ')}` : '';

    const [rows] = await pool.query(`
      SELECT
        o.id,
        o.id_local_trabalho,
        lt.NOME AS nomelocaltrabalho,
        o.id_setor_pai,
        sp.NOME AS nomesetorpai,
        o.id_setor_filho,
        sf.NOME AS nomesetorfilho,
        o.status,
        o.criado_em,
        o.atualizado_em
      FROM SF_ORGANOGRAMA o
      INNER JOIN SF_LOCAL_TRABALHO lt ON lt.ID = o.id_local_trabalho
      INNER JOIN SF_ORGANOGRAMA_SETOR sp ON sp.ID = o.id_setor_pai
      INNER JOIN SF_ORGANOGRAMA_SETOR sf ON sf.ID = o.id_setor_filho
      ${where}
      ORDER BY lt.NOME ASC, sp.NOME ASC, sf.NOME ASC
    `, params);

    return res.json({
      success: true,
      items: rows
    });
  } catch (error) {
    console.error('Erro ao listar organograma:', error);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar organograma.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// Buscar vínculo específico do organograma
app.get('/api/organograma/:id', async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();

    const id = Number(req.params.id);
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        o.id,
        o.id_local_trabalho,
        lt.NOME AS nomelocaltrabalho,
        o.id_setor_pai,
        sp.NOME AS nomesetorpai,
        o.id_setor_filho,
        sf.NOME AS nomesetorfilho,
        o.status,
        o.criado_em,
        o.atualizado_em
      FROM SF_ORGANOGRAMA o
      INNER JOIN SF_LOCAL_TRABALHO lt ON lt.ID = o.id_local_trabalho
      INNER JOIN SF_ORGANOGRAMA_SETOR sp ON sp.ID = o.id_setor_pai
      INNER JOIN SF_ORGANOGRAMA_SETOR sf ON sf.ID = o.id_setor_filho
      WHERE o.id = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: rows[0]
    });
  } catch (error) {
    console.error('Erro ao buscar vínculo do organograma:', error);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar vínculo do organograma.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// Criar vínculo do organograma
app.post('/api/organograma', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const id_local_trabalho = Number(req.body?.id_local_trabalho ?? req.body?.id_local_trabalho);
    const id_setor_pai = Number(req.body?.id_setor_pai ?? req.body?.id_setor_pai);
    const id_setor_filho = Number(req.body?.id_setor_filho ?? req.body?.id_setor_filho);
    const status = Number(req.body?.status ?? 1) ? 1 : 0;

    if (!id_local_trabalho || !id_setor_pai || !id_setor_filho) {
      return res.status(400).json({
        success: false,
        message: 'id_local_trabalho, id_setor_pai e id_setor_filho são obrigatórios.'
      });
    }

    if (id_setor_pai === id_setor_filho) {
      return res.status(400).json({
        success: false,
        message: 'O setor pai não pode ser igual ao setor filho.'
      });
    }

    const [localExiste] = await conn.query(
      'SELECT ID FROM SF_LOCAL_TRABALHO WHERE ID = ? LIMIT 1',
      [id_local_trabalho]
    );

    if (!localExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Local de trabalho não encontrado.'
      });
    }

    const [setorPaiExiste] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id_setor_pai]
    );

    if (!setorPaiExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor pai não encontrado.'
      });
    }

    const [setorFilhoExiste] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id_setor_filho]
    );

    if (!setorFilhoExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor filho não encontrado.'
      });
    }

    const [duplicado] = await conn.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA
      WHERE id_local_trabalho = ?
        AND id_setor_pai = ?
        AND id_setor_filho = ?
      LIMIT 1
    `, [id_local_trabalho, id_setor_pai, id_setor_filho]);

    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Este vínculo já está cadastrado.'
      });
    }

    const [result] = await conn.query(`
      INSERT INTO SF_ORGANOGRAMA (
        id_local_trabalho,
        id_setor_pai,
        id_setor_filho,
        status
      ) VALUES (?, ?, ?, ?)
    `, [
      id_local_trabalho,
      id_setor_pai,
      id_setor_filho,
      status
    ]);

    const [novoRegistro] = await conn.query(`
      SELECT
        o.id,
        o.id_local_trabalho,
        lt.NOME AS nomelocaltrabalho,
        o.id_setor_pai,
        sp.NOME AS nomesetorpai,
        o.id_setor_filho,
        sf.NOME AS nomesetorfilho,
        o.status,
        o.criado_em,
        o.atualizado_em
      FROM SF_ORGANOGRAMA o
      INNER JOIN SF_LOCAL_TRABALHO lt ON lt.ID = o.id_local_trabalho
      INNER JOIN SF_ORGANOGRAMA_SETOR sp ON sp.ID = o.id_setor_pai
      INNER JOIN SF_ORGANOGRAMA_SETOR sf ON sf.ID = o.id_setor_filho
      WHERE o.id = ?
      LIMIT 1
    `, [result.insertId]);

    return res.status(201).json({
      success: true,
      item: novoRegistro[0]
    });
  } catch (error) {
    console.error('Erro ao criar vínculo do organograma:', error);

    if (error?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Este vínculo já está cadastrado.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao criar vínculo do organograma.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// Atualizar vínculo do organograma
app.put('/api/organograma/:id', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const id = Number(req.params.id);
    const id_local_trabalho = Number(req.body?.id_local_trabalho ?? req.body?.id_local_trabalho);
    const id_setor_pai = Number(req.body?.id_setor_pai ?? req.body?.id_setor_pai);
    const id_setor_filho = Number(req.body?.id_setor_filho ?? req.body?.id_setor_filho);
    const status = Number(req.body?.status ?? 1) ? 1 : 0;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    if (!id_local_trabalho || !id_setor_pai || !id_setor_filho) {
      return res.status(400).json({
        success: false,
        message: 'id_local_trabalho, id_setor_pai e id_setor_filho são obrigatórios.'
      });
    }

    if (id_setor_pai === id_setor_filho) {
      return res.status(400).json({
        success: false,
        message: 'O setor pai não pode ser igual ao setor filho.'
      });
    }

    const [registroAtual] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!registroAtual.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    const [localExiste] = await conn.query(
      'SELECT ID FROM SF_LOCAL_TRABALHO WHERE ID = ? LIMIT 1',
      [id_local_trabalho]
    );

    if (!localExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Local de trabalho não encontrado.'
      });
    }

    const [setorPaiExiste] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id_setor_pai]
    );

    if (!setorPaiExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor pai não encontrado.'
      });
    }

    const [setorFilhoExiste] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id_setor_filho]
    );

    if (!setorFilhoExiste.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor filho não encontrado.'
      });
    }

    const [duplicado] = await conn.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA
      WHERE id_local_trabalho = ?
        AND id_setor_pai = ?
        AND id_setor_filho = ?
        AND ID <> ?
      LIMIT 1
    `, [id_local_trabalho, id_setor_pai, id_setor_filho, id]);

    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro vínculo com esses dados.'
      });
    }

    await conn.query(`
      UPDATE SF_ORGANOGRAMA
      SET
        id_local_trabalho = ?,
        id_setor_pai = ?,
        id_setor_filho = ?,
        status = ?
      WHERE ID = ?
    `, [
      id_local_trabalho,
      id_setor_pai,
      id_setor_filho,
      status,
      id
    ]);

    const [registroAtualizado] = await conn.query(`
      SELECT
        o.id,
        o.id_local_trabalho,
        lt.NOME AS nomelocaltrabalho,
        o.id_setor_pai,
        sp.NOME AS nomesetorpai,
        o.id_setor_filho,
        sf.NOME AS nomesetorfilho,
        o.status,
        o.criado_em,
        o.atualizado_em
      FROM SF_ORGANOGRAMA o
      INNER JOIN SF_LOCAL_TRABALHO lt ON lt.ID = o.id_local_trabalho
      INNER JOIN SF_ORGANOGRAMA_SETOR sp ON sp.ID = o.id_setor_pai
      INNER JOIN SF_ORGANOGRAMA_SETOR sf ON sf.ID = o.id_setor_filho
      WHERE o.ID = ?
      LIMIT 1
    `, [id]);

    return res.json({
      success: true,
      item: registroAtualizado[0]
    });
  } catch (error) {
    console.error('Erro ao atualizar vínculo do organograma:', error);

    if (error?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro vínculo com esses dados.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar vínculo do organograma.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// Excluir vínculo do organograma
app.delete('/api/organograma/:id', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [registro] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!registro.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    await conn.query('DELETE FROM SF_ORGANOGRAMA WHERE ID = ?', [id]);

    return res.json({
      success: true,
      message: 'Vínculo excluído com sucesso.'
    });
  } catch (error) {
    console.error('Erro ao excluir vínculo do organograma:', error);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir vínculo do organograma.',
      error: error.message
    });
  } finally {
    if (conn) conn.release();
  }
});


// =========================
// SETORES DO ORGANOGRAMA
// =========================

// Listar setores do organograma
app.get('/api/organograma-setores', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ID,
        NOME,
        DESCRICAO,
        STATUS,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_SETOR
      ORDER BY NOME ASC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar setores do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar setores do organograma.',
      error: err.message
    });
  }
});


// Buscar setor do organograma por id
app.get('/api/organograma-setores/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        ID,
        NOME,
        DESCRICAO,
        STATUS,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_SETOR
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor do organograma não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    console.error('Erro ao buscar setor do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar setor do organograma.',
      error: err.message
    });
  }
});


// Criar setor do organograma
app.post('/api/organograma-setores', async (req, res) => {
  try {
    const nome = String(req.body?.nome ?? '').trim();
    const descricao = String(req.body?.descricao ?? '').trim() || null;
    const status = Number(req.body?.status ?? 1) ? 1 : 0;


    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome do setor é obrigatório.'
      });
    }

    const [duplicado] = await pool.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA_SETOR
      WHERE UPPER(TRIM(NOME)) = UPPER(TRIM(?))
      LIMIT 1
    `, [nome]);


    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Já existe um setor do organograma com esse nome.'
      });
    }

    const [result] = await pool.query(`
      INSERT INTO SF_ORGANOGRAMA_SETOR (NOME, DESCRICAO, STATUS)
      VALUES (?, ?, ?)
    `, [nome, descricao, status]);

    const [itemRows] = await pool.query(`
      SELECT
        ID,
        NOME,
        DESCRICAO,
        STATUS,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_SETOR
      WHERE ID = ?
      LIMIT 1
    `, [result.insertId]);

    return res.status(201).json({
      success: true,
      item: itemRows[0]
    });
  } catch (err) {
    console.error('Erro ao cadastrar setor do organograma:', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'POST: /api/organograma-setores.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar setor do organograma.',
      error: err.message
    });
  }
});


// Atualizar setor do organograma
app.put('/api/organograma-setores/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const nome = String(req.body?.nome ?? '').trim();
    const descricao = String(req.body?.descricao ?? '').trim() || null;
    const status = Number(req.body?.status ?? 1) ? 1 : 0;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    if (!nome) {
      return res.status(400).json({
        success: false,
        message: 'Nome do setor é obrigatório.'
      });
    }

    const [atual] = await pool.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!atual.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor do organograma não encontrado.'
      });
    }

    const [duplicado] = await pool.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA_SETOR
      WHERE UPPER(TRIM(NOME)) = UPPER(TRIM(?))
        AND ID <> ?
      LIMIT 1
    `, [nome, id]);

    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro setor do organograma com esse nome.'
      });
    }

    await pool.query(`
      UPDATE SF_ORGANOGRAMA_SETOR
      SET
        NOME = ?,
        DESCRICAO = ?,
        STATUS = ?
      WHERE ID = ?
    `, [nome, descricao, status, id]);

    const [itemRows] = await pool.query(`
      SELECT
        ID,
        NOME,
        DESCRICAO,
        STATUS,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_SETOR
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    return res.json({
      success: true,
      item: itemRows[0]
    });
  } catch (err) {
    console.error('Erro ao atualizar setor do organograma:', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro setor do organograma com esse nome.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar setor do organograma.',
      error: err.message
    });
  }
});


// Excluir setor do organograma
app.delete('/api/organograma-setores/:id', async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();

    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [setor] = await conn.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!setor.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor do organograma não encontrado.'
      });
    }

    const [emUsoNoOrganograma] = await conn.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA
      WHERE id_setor_pai = ? OR id_setor_filho = ?
      LIMIT 1
    `, [id, id]);

    if (emUsoNoOrganograma.length) {
      return res.status(409).json({
        success: false,
        message: 'Não é possível excluir este setor porque ele está vinculado ao organograma.'
      });
    }

    const [emUsoPorUsuario] = await conn.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA_USUARIO_SETOR
      WHERE ID_SETOR_ORGANOGRAMA = ?
      LIMIT 1
    `, [id]);

    if (emUsoPorUsuario.length) {
      return res.status(409).json({
        success: false,
        message: 'Não é possível excluir este setor porque ele está vinculado a usuários.'
      });
    }

    await conn.query('DELETE FROM SF_ORGANOGRAMA_SETOR WHERE ID = ?', [id]);

    return res.json({
      success: true,
      message: 'Setor do organograma excluído com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao excluir setor do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir setor do organograma.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});


// =========================
// VÍNCULOS DE USUÁRIOS AO SETOR DO ORGANOGRAMA
// =========================

function normalizarPrecisaAprocavao(value) {
  const v = String(value ?? '').trim().toLowerCase();
  return v === 'sim' ? 'sim' : 'nao';
}

// Listar vínculos de usuários x setores do organograma
app.get('/api/organograma-usuarios-vinculos', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        vus.ID,
        vus.ID_USUARIO,
        u.NOME AS NOME_USUARIO,
        u.EMAIL AS EMAIL_USUARIO,
        vus.ID_SETOR_ORGANOGRAMA,
        s.NOME AS NOME_SETOR,
        vus.PRECISA_APROCAVAO,
        vus.STATUS,
        vus.CRIADO_EM,
        vus.ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_USUARIO_SETOR vus
      INNER JOIN SF_USUARIO u ON u.ID = vus.ID_USUARIO
      INNER JOIN SF_ORGANOGRAMA_SETOR s ON s.ID = vus.ID_SETOR_ORGANOGRAMA
      ORDER BY s.NOME ASC, u.NOME ASC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar vínculos de usuários do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar vínculos de usuários do organograma.',
      error: err.message
    });
  }
});

// Buscar vínculo de usuário x setor por id
app.get('/api/organograma-usuarios-vinculos/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        vus.ID,
        vus.ID_USUARIO,
        u.NOME AS NOME_USUARIO,
        u.EMAIL AS EMAIL_USUARIO,
        vus.ID_SETOR_ORGANOGRAMA,
        s.NOME AS NOME_SETOR,
        vus.PRECISA_APROCAVAO,
        vus.STATUS,
        vus.CRIADO_EM,
        vus.ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_USUARIO_SETOR vus
      INNER JOIN SF_USUARIO u ON u.ID = vus.ID_USUARIO
      INNER JOIN SF_ORGANOGRAMA_SETOR s ON s.ID = vus.ID_SETOR_ORGANOGRAMA
      WHERE vus.ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    console.error('Erro ao buscar vínculo de usuário do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar vínculo de usuário do organograma.',
      error: err.message
    });
  }
});

// Criar vínculo usuário x setor do organograma
app.post('/api/organograma-usuarios-vinculos', async (req, res) => {
  try {
    const idUsuario = Number(
      req.body?.id_usuario ??
      req.body?.idUsuario ??
      req.body?.idusuario
    );

    const idSetorOrganograma = Number(
      req.body?.id_setor_organograma ??
      req.body?.idSetorOrganograma ??
      req.body?.idsetororganograma
    );

    const precisaaprocavao = normalizarPrecisaAprocavao(
      req.body?.precisa_aprocavao ??
      req.body?.precisaAprocavao ??
      req.body?.precisaaprocavao ??
      req.body?.precisa_aprovacao ??
      req.body?.precisaAprovacao ??
      req.body?.precisaaprovacao
    );

    const status = Number(req.body?.status ?? 1) ? 1 : 0;

    if (!idUsuario || !idSetorOrganograma) {
      return res.status(400).json({
        success: false,
        message: 'id_usuario e id_setor_organograma são obrigatórios.'
      });
    }

    const [usuario] = await pool.query(
      'SELECT ID FROM SF_USUARIO WHERE ID = ? LIMIT 1',
      [idUsuario]
    );

    if (!usuario.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const [setor] = await pool.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [idSetorOrganograma]
    );

    if (!setor.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor do organograma não encontrado.'
      });
    }

    const [duplicado] = await pool.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA_USUARIO_SETOR
      WHERE ID_USUARIO = ?
        AND ID_SETOR_ORGANOGRAMA = ?
      LIMIT 1
    `, [idUsuario, idSetorOrganograma]);

    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Usuário já vinculado a este setor.'
      });
    }

    const [result] = await pool.query(`
      INSERT INTO SF_ORGANOGRAMA_USUARIO_SETOR
      (ID_USUARIO, ID_SETOR_ORGANOGRAMA, PRECISA_APROCAVAO, STATUS)
      VALUES (?, ?, ?, ?)
    `, [idUsuario, idSetorOrganograma, precisaaprocavao, status]);

    const [itemRows] = await pool.query(`
      SELECT
        vus.ID,
        vus.ID_USUARIO,
        u.NOME AS NOME_USUARIO,
        u.EMAIL AS EMAIL_USUARIO,
        vus.ID_SETOR_ORGANOGRAMA,
        s.NOME AS NOME_SETOR,
        vus.PRECISA_APROCAVAO,
        vus.STATUS,
        vus.CRIADO_EM,
        vus.ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_USUARIO_SETOR vus
      INNER JOIN SF_USUARIO u ON u.ID = vus.ID_USUARIO
      INNER JOIN SF_ORGANOGRAMA_SETOR s ON s.ID = vus.ID_SETOR_ORGANOGRAMA
      WHERE vus.ID = ?
      LIMIT 1
    `, [result.insertId]);

    return res.status(201).json({
      success: true,
      item: itemRows[0]
    });
  } catch (err) {
    console.error('Erro ao vincular usuário ao setor do organograma:', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Usuário já vinculado a este setor.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao vincular usuário ao setor do organograma.',
      error: err.message
    });
  }
});

// Atualizar vínculo usuário x setor do organograma
app.put('/api/organograma-usuarios-vinculos/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    const idUsuario = Number(
      req.body?.id_usuario ??
      req.body?.idUsuario ??
      req.body?.idusuario
    );

    const idSetorOrganograma = Number(
      req.body?.id_setor_organograma ??
      req.body?.idSetorOrganograma ??
      req.body?.idsetororganograma
    );

    const precisaaprocavao = normalizarPrecisaAprocavao(
      req.body?.precisa_aprocavao ??
      req.body?.precisaAprocavao ??
      req.body?.precisaaprocavao ??
      req.body?.precisa_aprovacao ??
      req.body?.precisaAprovacao ??
      req.body?.precisaaprovacao
    );

    const status = Number(req.body?.status ?? 1) ? 1 : 0;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    if (!idUsuario || !idSetorOrganograma) {
      return res.status(400).json({
        success: false,
        message: 'id_usuario e id_setor_organograma são obrigatórios.'
      });
    }

    const [atual] = await pool.query(
      'SELECT ID FROM SF_ORGANOGRAMA_USUARIO_SETOR WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!atual.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    const [usuario] = await pool.query(
      'SELECT ID FROM SF_USUARIO WHERE ID = ? LIMIT 1',
      [idUsuario]
    );

    if (!usuario.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const [setor] = await pool.query(
      'SELECT ID FROM SF_ORGANOGRAMA_SETOR WHERE ID = ? LIMIT 1',
      [idSetorOrganograma]
    );

    if (!setor.length) {
      return res.status(404).json({
        success: false,
        message: 'Setor do organograma não encontrado.'
      });
    }

    const [duplicado] = await pool.query(`
      SELECT ID
      FROM SF_ORGANOGRAMA_USUARIO_SETOR
      WHERE ID_USUARIO = ?
        AND ID_SETOR_ORGANOGRAMA = ?
        AND ID <> ?
      LIMIT 1
    `, [idUsuario, idSetorOrganograma, id]);

    if (duplicado.length) {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro vínculo com esses dados.'
      });
    }

    await pool.query(`
      UPDATE SF_ORGANOGRAMA_USUARIO_SETOR
      SET
        ID_USUARIO = ?,
        ID_SETOR_ORGANOGRAMA = ?,
        PRECISA_APROCAVAO = ?,
        STATUS = ?
      WHERE ID = ?
    `, [idUsuario, idSetorOrganograma, precisaaprocavao, status, id]);

    const [itemRows] = await pool.query(`
      SELECT
        vus.ID,
        vus.ID_USUARIO,
        u.NOME AS NOME_USUARIO,
        u.EMAIL AS EMAIL_USUARIO,
        vus.ID_SETOR_ORGANOGRAMA,
        s.NOME AS NOME_SETOR,
        vus.PRECISA_APROCAVAO,
        vus.STATUS,
        vus.CRIADO_EM,
        vus.ATUALIZADO_EM
      FROM SF_ORGANOGRAMA_USUARIO_SETOR vus
      INNER JOIN SF_USUARIO u ON u.ID = vus.ID_USUARIO
      INNER JOIN SF_ORGANOGRAMA_SETOR s ON s.ID = vus.ID_SETOR_ORGANOGRAMA
      WHERE vus.ID = ?
      LIMIT 1
    `, [id]);

    return res.json({
      success: true,
      item: itemRows[0]
    });
  } catch (err) {
    console.error('Erro ao atualizar vínculo de usuário do organograma:', err);

    if (err?.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({
        success: false,
        message: 'Já existe outro vínculo com esses dados.'
      });
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar vínculo de usuário do organograma.',
      error: err.message
    });
  }
});

// Excluir vínculo usuário x setor do organograma
app.delete('/api/organograma-usuarios-vinculos/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [atual] = await pool.query(
      'SELECT ID FROM SF_ORGANOGRAMA_USUARIO_SETOR WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!atual.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    await pool.query(
      'DELETE FROM SF_ORGANOGRAMA_USUARIO_SETOR WHERE ID = ?',
      [id]
    );

    return res.json({
      success: true,
      message: 'Vínculo excluído com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao excluir vínculo de usuário do organograma:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir vínculo de usuário do organograma.',
      error: err.message
    });
  }
});

// IMPORTAR USUÁRIOS VIA TEMPLATE

function somenteNumerosImportar(v) {
  return String(v ?? '').replace(/\D/g, '');
}

function excelDateToISO(valor) {
  if (!valor) return null;

  if (typeof valor === 'number') {
    const data = XLSX.SSF.parse_date_code(valor);
    if (!data) return null;

    const yyyy = String(data.y).padStart(4, '0');
    const mm = String(data.m).padStart(2, '0');
    const dd = String(data.d).padStart(2, '0');
    return `${yyyy}-${mm}-${dd}`;
  }

  const s = String(valor).trim();
  if (!s) return null;

  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (m) {
    const [, dd, mm, yyyy] = m;
    return `${yyyy}-${mm}-${dd}`;
  }

  return s.slice(0, 10);
}

async function obterOuCriarPorNome(conn, tabela, nome) {
  const valor = titleCaseNome(nome || '');
  if (!valor) return null;

  const [rows] = await conn.query(
    `SELECT ID, NOME FROM ${tabela} WHERE UPPER(TRIM(NOME)) = UPPER(TRIM(?)) LIMIT 1`,
    [valor]
  );

  if (rows.length) {
    return rows[0];
  }

  const [result] = await conn.query(
    `INSERT INTO ${tabela} (NOME) VALUES (?)`,
    [valor]
  );

  const novo = { ID: result.insertId, NOME: valor };
  return novo;
}

app.post('/api/gestao-usuarios-importar', uploadMemoria.single('arquivo'), async (req, res) => {
  let conn;

  try {
    if (!req.file?.buffer) {
      return res.status(400).json({
        success: false,
        message: 'Arquivo Excel é obrigatório.'
      });
    }

    const wb = XLSX.read(req.file.buffer, { type: 'buffer' });
    const primeiraAba = wb.SheetNames[0];
    const ws = wb.Sheets[primeiraAba];

    if (!ws) {
      return res.status(400).json({
        success: false,
        message: 'A primeira aba da planilha não foi encontrada.'
      });
    }

    const linhas = XLSX.utils.sheet_to_json(ws, { defval: '' });

    if (!linhas.length) {
      return res.status(400).json({
        success: false,
        message: 'A planilha está vazia.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    const sucessos = [];
    const ignoradosDetalhes = [];
    const erros = [];

    let inseridos = 0;
    let ignorados = 0;

    const gerarEmailTemporario = async (conn, cpf) => {
      const baseEmail = `${cpf}@temp.local`;

      const [emailBaseExistente] = await conn.query(
        `SELECT ID FROM SF_USUARIO WHERE EMAIL = ? LIMIT 1`,
        [baseEmail]
      );

      if (emailBaseExistente.length === 0) {
        return baseEmail;
      }

      let contador = 1;
      let emailAlternativo = `${cpf}.${contador}@temp.local`;

      while (true) {
        const [emailExistente] = await conn.query(
          `SELECT ID FROM SF_USUARIO WHERE EMAIL = ? LIMIT 1`,
          [emailAlternativo]
        );

        if (emailExistente.length === 0) {
          return emailAlternativo;
        }

        contador++;
        emailAlternativo = `${cpf}.${contador}@temp.local`;
      }
    };

    for (let i = 0; i < linhas.length; i++) {
      const linha = linhas[i];
      const numeroLinha = i + 2;

      try {
        const nome = titleCaseNome(linha['NOME']);
        const cpf = somenteNumerosImportar(linha['CPF']);
        const emailInformado = texto(linha['EMAIL'] || linha['E-MAIL']).toLowerCase();
        const telefone = somenteNumerosImportar(
          linha['TELEFONE'] || linha['CELULAR'] || linha['TELEFONE 1']
        );
        const dataNascimento = excelDateToISO(linha['DATA NASCIMENTO']);
        const dataAdmissao = excelDateToISO(linha['DATA ADMISSÃO'] || linha['DATA ADMISSAO']);
        const funcao = titleCaseNome(linha['FUNÇÃO'] || linha['FUNCAO'] || '');
        const setor = titleCaseNome(linha['SETOR']);
        const perfil = texto(linha['PERFIL']) || 'Colaborador';
        const status = texto(linha['STATUS']) || 'Ativo';
        const centroCusto = titleCaseNome(linha['CENTRO CUSTO']);
        const unidadeTrabalho = titleCaseNome(linha['UNIDADE TRABALHO']);

        if (!nome || !cpf || !dataNascimento || !setor || !perfil || !status) {
          const erroMsg = 'Campos obrigatórios ausentes: NOME, CPF, DATA NASCIMENTO, SETOR, PERFIL e STATUS.';

          erros.push({
            linha: numeroLinha,
            nome: nome || '',
            erro: erroMsg
          });

          continue;
        }

        const [cpfExistente] = await conn.query(
          `SELECT ID, NOME, CPF FROM SF_USUARIO WHERE CPF = ? LIMIT 1`,
          [cpf]
        );

        if (cpfExistente.length > 0) {
          ignorados++;

          ignoradosDetalhes.push({
            linha: numeroLinha,
            nome,
            cpf,
            message: 'CPF já cadastrado. Registro ignorado.'
          });

          continue;
        }

        let emailFinal = emailInformado;

        if (emailFinal) {
          const [emailExistente] = await conn.query(
            `SELECT ID, NOME, EMAIL FROM SF_USUARIO WHERE EMAIL = ? LIMIT 1`,
            [emailFinal]
          );

          if (emailExistente.length > 0) {
            ignorados++;

            ignoradosDetalhes.push({
              linha: numeroLinha,
              nome,
              cpf,
              email: emailFinal,
              message: 'E-mail já cadastrado. Registro ignorado.'
            });

            continue;
          }
        } else {
          emailFinal = await gerarEmailTemporario(conn, cpf);
        }

        if (setor) {
          await obterOuCriarPorNome(conn, 'SF_SETOR', setor);
        }

        if (funcao) {
          await obterOuCriarPorNome(conn, 'SF_FUNCAO', funcao);
        }

        if (unidadeTrabalho) {
          await obterOuCriarPorNome(conn, 'SF_LOCAL_TRABALHO', unidadeTrabalho);
        }

        if (centroCusto) {
          await obterOuCriarPorNome(conn, 'SF_CENTRO_CUSTO', centroCusto);
        }

        const senhaHash = await bcrypt.hash('123456', 12);

        const [result] = await conn.query(
          `INSERT INTO SF_USUARIO (
            NOME,
            EMAIL,
            SENHA,
            TELEFONE,
            PERFIL,
            SETOR,
            FUNCAO,
            DATA_ADMISSAO,
            CENTRO_CUSTO,
            LOCAL_TRABALHO,
            STATUS,
            CPF,
            DATA_NASCIMENTO,
            MUST_CHANGE_PASSWORD
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
          [
            nome,
            emailFinal,
            senhaHash,
            telefone || null,
            perfil,
            setor,
            funcao || null,
            dataAdmissao || null,
            centroCusto || null,
            unidadeTrabalho || null,
            status,
            cpf,
            dataNascimento
          ]
        );

        inseridos++;

        sucessos.push({
          linha: numeroLinha,
          id: result.insertId,
          nome,
          cpf,
          email: emailFinal,
          telefone: telefone || '',
          message: 'Usuário importado com sucesso.'
        });
      } catch (erroLinha) {
        console.error('[IMPORTAÇÃO] ERRO AO PROCESSAR LINHA:', {
          linha: numeroLinha,
          nome: titleCaseNome(linha['NOME']) || '',
          erro: erroLinha.message,
          stack: erroLinha.stack
        });

        erros.push({
          linha: numeroLinha,
          nome: titleCaseNome(linha['NOME']) || '',
          erro: erroLinha.message || 'Erro ao processar a linha.'
        });
      }
    }

    await conn.commit();

    const retorno = {
      success: true,
      message: 'Importação concluída.',
      totalLinhas: linhas.length,
      inseridos,
      ignorados,
      totalErros: erros.length,
      sucessos,
      ignoradosDetalhes,
      erros
    };

    return res.json(retorno);
  } catch (err) {
    console.error('\n========== [IMPORTAÇÃO USUÁRIOS] ERRO GERAL ==========');
    console.error('[IMPORTAÇÃO] Mensagem:', err.message);
    console.error('[IMPORTAÇÃO] Stack:', err.stack);

    if (conn) {
      try {
        await conn.rollback();
        console.error('[IMPORTAÇÃO] Rollback executado com sucesso.');
      } catch (rollbackErr) {
        console.error('[IMPORTAÇÃO] Erro ao executar rollback:', rollbackErr.message);
      }
    }

    return res.status(500).json({
      success: false,
      message: 'Erro ao importar planilha.',
      error: err.message
    });
  } finally {
    if (conn) {
      conn.release();
    }
  }
});

// notificação transferencias via WhatsApp

function obterNomeCentroCustoDestino(localDestino) {
  return (
    localDestino?.CENTRO_CUSTO ||
    localDestino?.centro_custo ||
    localDestino?.NOME ||
    localDestino?.nome ||
    localDestino?.DESCRICAO ||
    localDestino?.descricao ||
    ''
  ).toString().trim();
}

function normalizarNumeroWhatsAppBR(numero) {
  const digitos = String(numero || '').replace(/\D/g, '');

  if (!digitos) return null;
  if (digitos.length === 11) return `55${digitos}`;
  if (digitos.length === 13 && digitos.startsWith('55')) return digitos;

  return null;
}

function escapeHtml(valor) {
  return String(valor ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function listarUsuariosCentroCustoWhatsapp(conn, centroCusto) {
  const [rows] = await conn.query(
    `
    SELECT
      id,
      nome,
      EMAIL,
      TELEFONE,
      CENTRO_CUSTO,
      status
    FROM SF_USUARIO
    WHERE status = 'Ativo'
      AND TELEFONE IS NOT NULL
      AND TELEFONE <> ''
      AND TRIM(UPPER(CENTRO_CUSTO)) = TRIM(UPPER(?))
    `,
    [centroCusto]
  );

  return rows;
}

async function validarStatusInstanciaZApi() {
  const { clientToken } = getZApiConfig();
  const statusUrl = getZApiStatusUrl();

  console.log('[ZAPI] Validando status da instância...');
  console.log('[ZAPI] Status URL:', statusUrl);

  const resp = await fetch(statusUrl, {
    method: 'GET',
    headers: {
      ...(clientToken ? { 'Client-Token': clientToken } : {})
    }
  });

  const data = await resp.json().catch(() => null);

  console.log('[ZAPI] Status response code:', resp.status);
  console.log('[ZAPI] Status response body:', data);

  if (!resp.ok) {
    throw new Error(data?.message || data?.error || `Erro ao consultar status da instância Z-API. HTTP ${resp.status}`);
  }

  return data;
}

function montarHtmlCardTransferencia({
  acao,
  codigo,
  descricao,
  quantidade,
  unidade,
  localOrigem,
  localDestino,
  centroCusto,
  usuario,
  tipoTransferencia,
  observacao
}) {
  const titulo = acao === 'EDICAO'
    ? 'Transferência Atualizada'
    : 'Nova Transferência Registrada';

  const subtitulo = tipoTransferencia === 'EXTERNA'
    ? 'Movimentação externa de material'
    : 'Movimentação interna de material';

  const corPrincipal = acao === 'EDICAO' ? '#d97706' : '#0f766e';
  const badgeCor = tipoTransferencia === 'EXTERNA' ? '#b45309' : '#1d4ed8';
  const badgeTexto = tipoTransferencia === 'EXTERNA' ? 'EXTERNA' : 'LOCAL';

  return `
  <!DOCTYPE html>
  <html lang="pt-BR">
    <head>
      <meta charset="UTF-8" />
      <title>Transferência</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0;
          font-family: Arial, Helvetica, sans-serif;
          background: #eef2f7;
        }
        .canvas {
          width: 1080px;
          height: 1080px;
          padding: 48px;
          background:
            radial-gradient(circle at top right, rgba(15, 118, 110, 0.15), transparent 30%),
            linear-gradient(135deg, #f8fafc 0%, #eef2f7 100%);
        }
        .card {
          width: 100%;
          height: 100%;
          background: #ffffff;
          border-radius: 36px;
          box-shadow: 0 25px 80px rgba(15, 23, 42, 0.10);
          overflow: hidden;
          display: flex;
          flex-direction: column;
          border: 1px solid #e5e7eb;
        }
        .header {
          padding: 42px 46px 30px;
          background: linear-gradient(135deg, ${corPrincipal} 0%, #111827 100%);
          color: #fff;
        }
        .topline {
          font-size: 26px;
          letter-spacing: 1.5px;
          text-transform: uppercase;
          opacity: .9;
          margin-bottom: 18px;
          font-weight: 700;
        }
        .titulo {
          font-size: 52px;
          line-height: 1.1;
          font-weight: 800;
          margin: 0 0 12px;
        }
        .subtitulo {
          font-size: 28px;
          line-height: 1.4;
          opacity: .92;
          margin: 0;
        }
        .content {
          padding: 42px 46px;
          display: flex;
          flex-direction: column;
          gap: 24px;
          flex: 1;
        }
        .badge {
          align-self: flex-start;
          background: ${badgeCor};
          color: white;
          padding: 10px 18px;
          border-radius: 999px;
          font-size: 24px;
          font-weight: 700;
          letter-spacing: .5px;
        }
        .grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 18px;
        }
        .item, .item-full {
          background: #f8fafc;
          border: 1px solid #e5e7eb;
          border-radius: 24px;
          padding: 22px 24px;
        }
        .item-full {
          grid-column: 1 / -1;
        }
        .label {
          font-size: 20px;
          font-weight: 700;
          color: #64748b;
          text-transform: uppercase;
          letter-spacing: .6px;
          margin-bottom: 10px;
        }
        .valor {
          font-size: 30px;
          color: #0f172a;
          font-weight: 700;
          line-height: 1.35;
          word-break: break-word;
        }
        .footer {
          margin-top: auto;
          padding: 26px 46px 34px;
          border-top: 1px solid #e5e7eb;
          display: flex;
          justify-content: space-between;
          align-items: center;
          color: #64748b;
          font-size: 22px;
        }
        .footer strong {
          color: #0f172a;
        }
      </style>
    </head>
    <body>
      <div class="canvas">
        <div class="card">
          <div class="header">
            <div class="topline">Controle de Estoque</div>
            <h1 class="titulo">${escapeHtml(titulo)}</h1>
            <p class="subtitulo">${escapeHtml(subtitulo)}</p>
          </div>

          <div class="content">
            <div class="badge">${escapeHtml(badgeTexto)}</div>

            <div class="grid">
              <div class="item">
                <div class="label">Código</div>
                <div class="valor">${escapeHtml(codigo || '—')}</div>
              </div>

              <div class="item">
                <div class="label">Quantidade</div>
                <div class="valor">${escapeHtml(String(quantidade))} ${escapeHtml(unidade || 'UN')}</div>
              </div>

              <div class="item-full">
                <div class="label">Material</div>
                <div class="valor">${escapeHtml(descricao || 'Material não informado')}</div>
              </div>

              <div class="item">
                <div class="label">Origem</div>
                <div class="valor">${escapeHtml(localOrigem || '—')}</div>
              </div>

              <div class="item">
                <div class="label">Destino</div>
                <div class="valor">${escapeHtml(localDestino || '—')}</div>
              </div>

              <div class="item">
                <div class="label">Usuário</div>
                <div class="valor">${escapeHtml(usuario || 'SISTEMA')}</div>
              </div>

              ${
                observacao
                  ? `
                    <div class="item-full">
                      <div class="label">Observação</div>
                      <div class="valor">${escapeHtml(observacao)}</div>
                    </div>
                  `
                  : ''
              }
            </div>
          </div>

          <div class="footer">
            <div><strong>Status:</strong> ${escapeHtml(acao === 'EDICAO' ? 'Atualizada' : 'Registrada')}</div>
            <div>Notificação automática</div>
          </div>
        </div>
      </div>
    </body>
  </html>
  `;
}

async function gerarImagemTransferenciaBase64(dados) {
  const html = montarHtmlCardTransferencia(dados);

  const browser = await puppeteer.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox']
  });

  try {
    const page = await browser.newPage();
    await page.setViewport({ width: 1080, height: 1080, deviceScaleFactor: 1 });
    await page.setContent(html, { waitUntil: 'networkidle0' });

    const buffer = await page.screenshot({
      type: 'png'
    });

    const base64 = `data:image/png;base64,${buffer.toString('base64')}`;
    return base64;
  } finally {
    await browser.close();
  }
}

async function enviarImagemWhatsAppZApi({ telefone, imageBase64, caption = '' }) {
  const { clientToken } = getZApiConfig();
  const endpoint = getZApiSendImageUrl();

  const numero = normalizarNumeroWhatsAppBR(telefone);

  if (!numero) {
    throw new Error(`Número inválido para WhatsApp: ${telefone}`);
  }

  const payload = {
    phone: numero,
    image: imageBase64,
    caption,
    viewOnce: false
  };

  console.log('[ZAPI][IMAGE] Enviando imagem...');
  console.log('[ZAPI][IMAGE] Endpoint:', endpoint);
  console.log('[ZAPI][IMAGE] Instance ID:', process.env.ZAPI_INSTANCE_ID);
  console.log('[ZAPI][IMAGE] Telefone original:', telefone);
  console.log('[ZAPI][IMAGE] Telefone normalizado:', numero);
  console.log('[ZAPI][IMAGE] Caption:', caption);

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(clientToken ? { 'Client-Token': clientToken } : {})
    },
    body: JSON.stringify(payload)
  });

  const data = await resp.json().catch(() => null);

  console.log('[ZAPI][IMAGE] Response code:', resp.status);
  console.log('[ZAPI][IMAGE] Response body:', data);

  if (!resp.ok) {
    throw new Error(data?.message || data?.error || `Erro ao enviar imagem via Z-API. HTTP ${resp.status}`);
  }

  return data;
}

async function notificarUsuariosCentroCustoTransferenciaImagem(conn, {
  centroCusto,
  dadosImagem,
  caption
}) {
  if (!centroCusto) return [];

  const usuarios = await listarUsuariosCentroCustoWhatsapp(conn, centroCusto);
  const resultados = [];

  if (!usuarios.length) {
    console.log('[WHATSAPP][IMAGE] Nenhum usuário encontrado para o centro de custo:', centroCusto);
    return resultados;
  }

  const imageBase64 = await gerarImagemTransferenciaBase64(dadosImagem);

  for (const usuario of usuarios) {
    try {
      const numero = normalizarNumeroWhatsAppBR(usuario.TELEFONE);

      if (!numero) {
        resultados.push({
          usuarioId: usuario.id,
          nome: usuario.nome,
          telefone: usuario.TELEFONE,
          sucesso: false,
          erro: 'Telefone inválido'
        });
        continue;
      }

      const retorno = await enviarImagemWhatsAppZApi({
        telefone: numero,
        imageBase64,
        caption
      });

      resultados.push({
        usuarioId: usuario.id,
        nome: usuario.nome,
        telefone: numero,
        sucesso: true,
        retorno
      });
    } catch (err) {
      console.error(`Erro ao notificar com imagem ${usuario.nome}:`, err.message);

      resultados.push({
        usuarioId: usuario.id,
        nome: usuario.nome,
        telefone: usuario.TELEFONE,
        sucesso: false,
        erro: err.message
      });
    }
  }

  return resultados;
}

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

    const centroCustoDestino = obterNomeCentroCustoDestino(localDestino);

    const dadosImagem = {
      acao: 'CRIACAO',
      codigo: produto?.CODIGO || produto?.codigo || '',
      descricao: produto?.DESCRICAO || produto?.descricao || 'Material',
      quantidade,
      unidade: unidade || produto?.unidade || 'UN',
      localOrigem: localOrigem?.NOME || localOrigem?.nome || '',
      localDestino: localDestino?.NOME || localDestino?.nome || '',
      centroCusto: centroCustoDestino,
      usuario,
      tipoTransferencia,
      observacao
    };

    const caption = '📦 Nova transferência registrada no sistema.';

    try {
      await validarStatusInstanciaZApi();

      await notificarUsuariosCentroCustoTransferenciaImagem(conn, {
        centroCusto: centroCustoDestino,
        dadosImagem,
        caption
      });
    } catch (erroNotificacao) {
      console.error('Transferência criada com sucesso, mas houve falha ao enviar imagem via WhatsApp:', erroNotificacao);
    }

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

    const centroCustoDestino = obterNomeCentroCustoDestino(localDestino);

    const dadosImagem = {
      acao: 'EDICAO',
      codigo: produto?.CODIGO || produto?.codigo || '',
      descricao: produto?.DESCRICAO || produto?.descricao || 'Material',
      quantidade: quantidadeNova,
      unidade: atual.UNIDADE || produto?.unidade || 'UN',
      localOrigem: localOrigem?.NOME || localOrigem?.nome || '',
      localDestino: localDestino?.NOME || localDestino?.nome || '',
      centroCusto: centroCustoDestino,
      usuario,
      tipoTransferencia: atual.TIPO_TRANSFERENCIA || req.body.tipoTransferencia || 'LOCAL',
      observacao
    };

    const caption = '🔄 Transferência atualizada no sistema.';

    try {
      await validarStatusInstanciaZApi();

      await notificarUsuariosCentroCustoTransferenciaImagem(conn, {
        centroCusto: centroCustoDestino,
        dadosImagem,
        caption
      });
    } catch (erroNotificacao) {
      console.error('Transferência editada com sucesso, mas houve falha ao enviar imagem via WhatsApp:', erroNotificacao);
    }

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



// Notificação monitoramento de Ping  //
// ---------------------------------- //

app.get('/apiusuarios', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();
    const items = await listarUsuariosAtivosComTelefone(conn);

    return res.json({
      success: true,
      items
    });
  } catch (err) {
    console.error('Erro ao listar usuários:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar usuários.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

function parseIntSeguro(valor, padrao = 0) {
  const n = Number.parseInt(valor, 10);
  return Number.isFinite(n) ? n : padrao;
}

async function listarUsuariosAtivosComTelefone(conn) {
  const [rows] = await conn.query(`
    SELECT
      id,
      nome,
      EMAIL,
      TELEFONE,
      CENTRO_CUSTO,
      status
    FROM SF_USUARIO
    WHERE status = 'Ativo'
      AND TELEFONE IS NOT NULL
      AND TELEFONE <> ''
    ORDER BY nome
  `);

  return rows;
}

async function listarContatosMonitor(conn, monitorId) {
  const [rows] = await conn.query(
    `
    SELECT
      c.ID,
      c.MONITOR_ID,
      c.TIPO_CONTATO,
      c.USUARIO_ID,
      c.NOME_CONTATO,
      c.TELEFONE,
      c.ATIVO,
      u.nome AS USUARIO_NOME,
      u.EMAIL AS USUARIO_EMAIL
    FROM SF_PING_MONITOR_CONTATO c
    LEFT JOIN SF_USUARIO u ON u.id = c.USUARIO_ID
    WHERE c.MONITOR_ID = ?
      AND c.ATIVO = '1'
    ORDER BY c.ID ASC
    `,
    [monitorId]
  );

  return rows;
}

async function verificarPingHost(ip) {
  const resp = await ping.promise.probe(ip, {
    timeout: 5,
    extra: ['-c', '1']
  });

  return {
    alive: !!resp.alive,
    time: resp.time ? Number(resp.time) : null,
    output: resp.output || ''
  };
}

function montarMensagemAlertaPing({ equipamento, ip, localizacao, status, tempoMs, erro }) {
  const base = [
    `🚨 ALERTA DE PING`,
    ``,
    `Equipamento: ${equipamento}`,
    `IP: ${ip}`,
    `Local: ${localizacao}`,
    `Status: ${status}`,
    tempoMs != null ? `Tempo: ${tempoMs} ms` : null,
    erro ? `Erro: ${erro}` : null,
    `Data/Hora: ${new Date().toLocaleString('pt-BR')}`
  ].filter(Boolean);

  return base.join('\n');
}

async function obterContatosParaEnvio(conn, monitorId) {
  const contatos = await listarContatosMonitor(conn, monitorId);
  const saida = [];
  const usados = new Set();

  for (const c of contatos) {
    let nome = c.NOME_CONTATO || c.USUARIO_NOME || 'Contato';
    let telefone = c.TELEFONE;

    if (c.TIPO_CONTATO === 'USUARIO' && c.USUARIO_ID) {
      telefone = c.TELEFONE || '';
      nome = c.USUARIO_NOME || nome;
    }

    const normalizado = normalizarNumeroWhatsAppBR(telefone);
    if (!normalizado) continue;

    const chave = `${normalizado}`;
    if (usados.has(chave)) continue;
    usados.add(chave);

    saida.push({
      nome,
      telefone: normalizado,
      tipo: c.TIPO_CONTATO
    });
  }

  return saida;
}

async function enviarWhatsAppParaLista({ lista, mensagem }) {
  const resultados = [];

  for (const item of lista) {
    try {
      const retorno = await enviarTextoWhatsAppZApi({
        telefone: item.telefone,
        message: mensagem
      });

      resultados.push({
        nome: item.nome,
        telefone: item.telefone,
        sucesso: true,
        retorno
      });
    } catch (err) {
      resultados.push({
        nome: item.nome,
        telefone: item.telefone,
        sucesso: false,
        erro: err.message
      });
    }
  }

  return resultados;
}

async function enviarTextoWhatsAppZApi({ telefone, message }) {
  const { clientToken } = getZApiConfig();
  const endpoint = getZApiSendTextUrl();

  const numero = normalizarNumeroWhatsAppBR(telefone);
  if (!numero) {
    throw new Error(`Número inválido para WhatsApp: ${telefone}`);
  }

  const payload = {
    phone: numero,
    message
  };

  const resp = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(clientToken ? { 'Client-Token': clientToken } : {})
    },
    body: JSON.stringify(payload)
  });

  const data = await resp.json().catch(() => null);

  if (!resp.ok) {
    throw new Error(data?.message || data?.error || `Erro ao enviar WhatsApp. HTTP ${resp.status}`);
  }

  return data;
}

app.post('/api/ping-monitor', async (req, res) => {
  let conn;

  try {
    const ip = textolivreTr(req.body.ip, 45);
    const equipamento = textolivreTr(req.body.equipamento, 150);
    const localizacao = textolivreTr(req.body.localizacao, 150);
    const intervaloMinutos = parseIntSeguro(req.body.intervaloMinutos, 5);
    const ativo = String(req.body.ativo ?? '1') === '1' ? '1' : '0';
    const enviarWhatsApp = String(req.body.enviarWhatsApp ?? '1') === '1' ? '1' : '0';
    const observacao = textolivreTr(req.body.observacao, 255);
    const usuarioCadastro = textolivreTr(req.body.usuarioCadastro, 150) || 'SISTEMA';

    if (!ip || !equipamento || !localizacao) {
      return res.status(400).json({
        success: false,
        message: 'Informe IP, equipamento e localizacao.'
      });
    }

    if (!(intervaloMinutos > 0)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um intervalo válido em minutos.'
      });
    }

    conn = await pool.getConnection();

    const [result] = await conn.query(
      `
      INSERT INTO SF_PING_MONITOR
        (IP, EQUIPAMENTO, LOCALIZACAO, INTERVALO_MINUTOS, ATIVO, ENVIAR_WHATSAPP, OBSERVACAO, USUARIO_CADASTRO)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [ip, equipamento, localizacao, intervaloMinutos, ativo, enviarWhatsApp, observacao || null, usuarioCadastro]
    );

    return res.json({
      success: true,
      id: result.insertId,
      message: 'Monitor cadastrado com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao cadastrar monitor:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar monitor.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get('/api/ping-monitor', async (req, res) => {
  let conn;

  try {
    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT *
      FROM SF_PING_MONITOR
      ORDER BY ID DESC
    `);

    return res.json({ success: true, items: rows });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar monitores.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.put('/api/ping-monitor/:id', async (req, res) => {
  let conn;

  try {
    const id = Number(req.params.id);
    const ip = textolivreTr(req.body.ip, 45);
    const equipamento = textolivreTr(req.body.equipamento, 150);
    const localizacao = textolivreTr(req.body.localizacao, 150);
    const intervaloMinutos = parseIntSeguro(req.body.intervaloMinutos, 5);
    const ativo = String(req.body.ativo ?? '1') === '1' ? '1' : '0';
    const enviarWhatsApp = String(req.body.enviarWhatsApp ?? '1') === '1' ? '1' : '0';
    const observacao = textolivreTr(req.body.observacao, 255);

    if (!id) {
      return res.status(400).json({ success: false, message: 'ID inválido.' });
    }

    conn = await pool.getConnection();

    const [result] = await conn.query(
      `
      UPDATE SF_PING_MONITOR
      SET IP = ?, EQUIPAMENTO = ?, LOCALIZACAO = ?, INTERVALO_MINUTOS = ?, ATIVO = ?, ENVIAR_WHATSAPP = ?, OBSERVACAO = ?
      WHERE ID = ?
      `,
      [ip, equipamento, localizacao, intervaloMinutos, ativo, enviarWhatsApp, observacao || null, id]
    );

    return res.json({
      success: true,
      affectedRows: result.affectedRows,
      message: 'Monitor atualizado com sucesso.'
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar monitor.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/ping-monitor/:id/contatos', async (req, res) => {
  let conn;

  try {
    const monitorId = Number(req.params.id);
    const contatos = Array.isArray(req.body.contatos) ? req.body.contatos : [];

    if (!monitorId) {
      return res.status(400).json({ success: false, message: 'Monitor inválido.' });
    }

    if (!contatos.length) {
      return res.status(400).json({ success: false, message: 'Informe ao menos um contato.' });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    await conn.query(`DELETE FROM SF_PING_MONITOR_CONTATO WHERE MONITOR_ID = ?`, [monitorId]);

    for (const item of contatos) {
      const tipoContato = String(item.tipoContato || 'MANUAL').toUpperCase();
      const usuarioId = item.usuarioId ? Number(item.usuarioId) : null;
      const nomeContato = textolivreTr(item.nomeContato, 150);
      const telefone = textolivreTr(item.telefone, 20);

      if (!telefone) continue;

      await conn.query(
        `
        INSERT INTO SF_PING_MONITOR_CONTATO
          (MONITOR_ID, TIPO_CONTATO, USUARIO_ID, NOME_CONTATO, TELEFONE)
        VALUES (?, ?, ?, ?, ?)
        `,
        [
          monitorId,
          ['USUARIO', 'MANUAL'].includes(tipoContato) ? tipoContato : 'MANUAL',
          usuarioId || null,
          nomeContato || null,
          telefone
        ]
      );
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Contatos salvos com sucesso.'
    });
  } catch (err) {
    if (conn) await conn.rollback().catch(() => {});
    return res.status(500).json({
      success: false,
      message: 'Erro ao salvar contatos.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.post('/api/ping-monitor/verificar', async (req, res) => {
  let conn;

  console.log('[PING] Iniciando verificação manual', {
    body: req.body,
    dataHora: new Date().toISOString()
  });

  try {
    const idMonitor = Number(req.body.idMonitor);
    console.log('[PING] idMonitor recebido:', idMonitor);

    if (!idMonitor) {
      console.log('[PING] idMonitor inválido');
      return res.status(400).json({
        success: false,
        message: 'Informe idMonitor.'
      });
    }

    console.log('[PING] Obtendo conexão com banco...');
    conn = await pool.getConnection();
    console.log('[PING] Conexão obtida com sucesso');

    console.log('[PING] Buscando monitor no banco...', { idMonitor });
    const [rows] = await conn.query(
      `SELECT * FROM SF_PING_MONITOR WHERE ID = ? LIMIT 1`,
      [idMonitor]
    );

    const monitor = rows[0];
    console.log('[PING] Resultado da busca do monitor:', monitor);

    if (!monitor) {
      console.log('[PING] Monitor não encontrado', { idMonitor });
      return res.status(404).json({
        success: false,
        message: 'Monitor não encontrado.'
      });
    }

    const statusAnterior = monitor.STATUS_ATUAL || 'UNKNOWN';
    console.log('[PING] Status anterior:', statusAnterior);

    console.log('[PING] Executando ping no host...', {
      ip: monitor.IP,
      equipamento: monitor.EQUIPAMENTO,
      localizacao: monitor.LOCALIZACAO
    });

    const resultadoPing = await verificarPingHost(monitor.IP);
    console.log('[PING] Resultado do ping:', resultadoPing);

    const statusNovo = resultadoPing.alive ? 'UP' : 'DOWN';
    const agora = new Date();

    const qtdFalhas = resultadoPing.alive
      ? 0
      : Number(monitor.QTD_FALHAS_CONSECUTIVAS || 0) + 1;

    const qtdSucessos = resultadoPing.alive
      ? Number(monitor.QTD_SUCESSOS_CONSECUTIVOS || 0) + 1
      : 0;

    console.log('[PING] Status calculado após verificação:', {
      statusAnterior,
      statusNovo,
      qtdFalhas,
      qtdSucessos,
      agora
    });

    console.log('[PING] Atualizando tabela SF_PING_MONITOR...');
    await conn.query(
      `
      UPDATE SF_PING_MONITOR
      SET
        STATUS_ATUAL = ?,
        ULTIMA_VERIFICACAO = ?,
        ULTIMO_OK = ?,
        ULTIMA_FALHA = ?,
        QTD_FALHAS_CONSECUTIVAS = ?,
        QTD_SUCESSOS_CONSECUTIVOS = ?
      WHERE ID = ?
      `,
      [
        statusNovo,
        agora,
        resultadoPing.alive ? agora : monitor.ULTIMO_OK,
        !resultadoPing.alive ? agora : monitor.ULTIMA_FALHA,
        qtdFalhas,
        qtdSucessos,
        idMonitor
      ]
    );
    console.log('[PING] Monitor atualizado com sucesso');

    console.log('[PING] Inserindo log em SF_PING_MONITOR_LOG...');
    const [logResult] = await conn.query(
      `
      INSERT INTO SF_PING_MONITOR_LOG
        (MONITOR_ID, IP, STATUS_ANTERIOR, STATUS_NOVO, TEMPO_MS, ERRO, DATA_VERIFICACAO)
      VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        idMonitor,
        monitor.IP,
        statusAnterior,
        statusNovo,
        resultadoPing.alive ? resultadoPing.time : null,
        resultadoPing.alive ? null : resultadoPing.output || 'Host indisponível',
        agora
      ]
    );

    console.log('[PING] Log inserido com sucesso', {
      logId: logResult.insertId
    });

    let notificacao = null;

    const houveMudanca = statusAnterior !== statusNovo;
    const deveNotificar =
      monitor.ENVIAR_WHATSAPP === '1' &&
      (
        (statusNovo === 'DOWN' && qtdFalhas >= 1 && houveMudanca) ||
        (statusNovo === 'UP' && houveMudanca)
      );

    console.log('[PING] Avaliação de notificação:', {
      enviarWhatsApp: monitor.ENVIAR_WHATSAPP,
      houveMudanca,
      deveNotificar,
      statusAnterior,
      statusNovo
    });

    if (deveNotificar) {
      console.log('[PING] Buscando contatos para envio...', { idMonitor });
      const contatos = await obterContatosParaEnvio(conn, idMonitor);
      console.log('[PING] Contatos encontrados:', contatos);

      if (contatos.length) {
        const mensagem = montarMensagemAlertaPing({
          equipamento: monitor.EQUIPAMENTO,
          ip: monitor.IP,
          localizacao: monitor.LOCALIZACAO,
          status: statusNovo,
          tempoMs: resultadoPing.time,
          erro: resultadoPing.alive ? null : resultadoPing.output
        });

        console.log('[PING] Mensagem montada para envio:');
        console.log(mensagem);

        console.log('[PING] Enviando WhatsApp para lista...');
        notificacao = await enviarWhatsAppParaLista({
          lista: contatos,
          mensagem
        });

        console.log('[PING] Resultado do envio WhatsApp:', notificacao);

        console.log('[PING] Atualizando log como notificado...');
        await conn.query(
          `UPDATE SF_PING_MONITOR_LOG SET NOTIFICADO = '1', DATA_ENVIO_NOTIFICACAO = ? WHERE ID = ?`,
          [new Date(), logResult.insertId]
        );
        console.log('[PING] Log atualizado como notificado');
      } else {
        console.log('[PING] Nenhum contato válido encontrado para notificação');
      }
    } else {
      console.log('[PING] Notificação não será enviada');
    }

    console.log('[PING] Finalizando verificação com sucesso', {
      idMonitor,
      statusAnterior,
      statusNovo
    });

    return res.json({
      success: true,
      idMonitor,
      statusAnterior,
      statusNovo,
      ping: resultadoPing,
      notificacao
    });
  } catch (err) {
    console.error('[PING] Erro ao verificar monitor:', {
      message: err.message,
      stack: err.stack
    });

    return res.status(500).json({
      success: false,
      message: 'Erro ao verificar ping.',
      error: err.message
    });
  } finally {
    if (conn) {
      console.log('[PING] Liberando conexão com banco');
      conn.release();
    }
  }
});

async function verificarMonitoresPendentes(conn) {
  const [rows] = await conn.query(`
    SELECT *
    FROM SF_PING_MONITOR
    WHERE ATIVO = '1'
    ORDER BY ID ASC
  `);

  const agora = Date.now();
  const resultados = [];

  for (const monitor of rows) {
    const ultima = monitor.ULTIMA_VERIFICACAO ? new Date(monitor.ULTIMA_VERIFICACAO).getTime() : 0;
    const intervaloMs = Number(monitor.INTERVALO_MINUTOS || 5) * 60 * 1000;

    if (ultima && agora - ultima < intervaloMs) {
      continue;
    }

    try {
      const resp = await fetch(`http://localhost:3000/api/ping-monitor/verificar-interno/${monitor.ID}`, {
        method: 'POST'
      }).catch(() => null);

      resultados.push({
        id: monitor.ID,
        executado: true,
        ok: !!resp
      });
    } catch (err) {
      resultados.push({
        id: monitor.ID,
        executado: false,
        erro: err.message
      });
    }
  }

  return resultados;
}

async function rotinaPingMonitoramento() {
  let conn;

  try {
    conn = await pool.getConnection();
    const [rows] = await conn.query(`
      SELECT *
      FROM SF_PING_MONITOR
      WHERE ATIVO = '1'
      ORDER BY ID ASC
    `);

    for (const monitor of rows) {
      const ultima = monitor.ULTIMA_VERIFICACAO ? new Date(monitor.ULTIMA_VERIFICACAO).getTime() : 0;
      const intervaloMs = Number(monitor.INTERVALO_MINUTOS || 5) * 60 * 1000;
      const agora = Date.now();

      if (ultima && agora - ultima < intervaloMs) continue;

      try {
        const statusAnterior = monitor.STATUS_ATUAL || 'UNKNOWN';
        const resultadoPing = await verificarPingHost(monitor.IP);
        const statusNovo = resultadoPing.alive ? 'UP' : 'DOWN';
        const dataAgora = new Date();

        const qtdFalhas = resultadoPing.alive
          ? 0
          : Number(monitor.QTD_FALHAS_CONSECUTIVAS || 0) + 1;

        const qtdSucessos = resultadoPing.alive
          ? Number(monitor.QTD_SUCESSOS_CONSECUTIVOS || 0) + 1
          : 0;

        await conn.query(
          `
          UPDATE SF_PING_MONITOR
          SET STATUS_ATUAL = ?, ULTIMA_VERIFICACAO = ?, ULTIMO_OK = ?, ULTIMA_FALHA = ?, QTD_FALHAS_CONSECUTIVAS = ?, QTD_SUCESSOS_CONSECUTIVOS = ?
          WHERE ID = ?
          `,
          [
            statusNovo,
            dataAgora,
            resultadoPing.alive ? dataAgora : monitor.ULTIMO_OK,
            !resultadoPing.alive ? dataAgora : monitor.ULTIMA_FALHA,
            qtdFalhas,
            qtdSucessos,
            monitor.ID
          ]
        );

        const [logResult] = await conn.query(
          `
          INSERT INTO SF_PING_MONITOR_LOG
            (MONITOR_ID, IP, STATUS_ANTERIOR, STATUS_NOVO, TEMPO_MS, ERRO, DATA_VERIFICACAO)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          `,
          [
            monitor.ID,
            monitor.IP,
            statusAnterior,
            statusNovo,
            resultadoPing.alive ? resultadoPing.time : null,
            resultadoPing.alive ? null : resultadoPing.output || 'Host indisponível',
            dataAgora
          ]
        );

        const houveMudanca = statusAnterior !== statusNovo;
        const deveNotificar =
          monitor.ENVIAR_WHATSAPP === '1' &&
          (
            (statusNovo === 'DOWN' && houveMudanca) ||
            (statusNovo === 'UP' && houveMudanca)
          );

        if (deveNotificar) {
          const contatos = await obterContatosParaEnvio(conn, monitor.ID);
          if (contatos.length) {
            const mensagem = montarMensagemAlertaPing({
              equipamento: monitor.EQUIPAMENTO,
              ip: monitor.IP,
              localizacao: monitor.LOCALIZACAO,
              status: statusNovo,
              tempoMs: resultadoPing.time,
              erro: resultadoPing.alive ? null : resultadoPing.output
            });

            const retornoEnvio = await enviarWhatsAppParaLista({
              lista: contatos,
              mensagem
            });

            await conn.query(
              `UPDATE SF_PING_MONITOR_LOG SET NOTIFICADO = '1', DATA_ENVIO_NOTIFICACAO = ? WHERE ID = ?`,
              [new Date(), logResult.insertId]
            );

            console.log('Notificação enviada', monitor.ID, retornoEnvio);
          }
        }
      } catch (err) {
        console.error(`Erro ao verificar monitor ${monitor.ID}:`, err.message);
      }
    }
  } catch (err) {
    console.error('Erro na rotina de monitoramento:', err.message);
  } finally {
    if (conn) conn.release();
  }
}


app.delete('/api/ping-monitor/:id', async (req, res) => {
  let conn;

  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    await conn.query(
      'DELETE FROM SF_PING_MONITOR_CONTATO WHERE MONITOR_ID = ?',
      [id]
    );

    const [result] = await conn.query(
      'DELETE FROM SF_PING_MONITOR WHERE ID = ?',
      [id]
    );

    if (result.affectedRows === 0) {
      await conn.rollback();
      return res.status(404).json({
        success: false,
        message: 'Monitor não encontrado.'
      });
    }

    await conn.commit();

    return res.json({
      success: true,
      message: 'Monitor e contatos vinculados excluídos com sucesso.'
    });
  } catch (err) {
    if (conn) await conn.rollback();

    console.error('Erro ao excluir monitor:', err);

    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir monitor.',
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/api/ping-monitor/:id/contatos", async (req, res) => {
  let conn;

  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        success: false,
        message: "ID inválido."
      });
    }

    conn = await pool.getConnection();

    const [rows] = await conn.query(`
      SELECT
        c.ID,
        c.MONITOR_ID,
        c.TIPO_CONTATO,
        c.USUARIO_ID,
        c.NOME_CONTATO,
        c.TELEFONE,
        c.ATIVO,
        u.nome AS USUARIO_NOME,
        u.EMAIL AS USUARIO_EMAIL
      FROM SF_PING_MONITOR_CONTATO c
      LEFT JOIN SF_USUARIO u ON u.id = c.USUARIO_ID
      WHERE c.MONITOR_ID = ?
      ORDER BY c.ID ASC
    `, [id]);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Erro ao carregar contatos do monitor.",
      error: err.message
    });
  } finally {
    if (conn) conn.release();
  }
});

// DF-e Certificado

const dfeSessions = new Map();

function gerarSessionIdDfe() {
  return crypto.randomBytes(16).toString('hex');
}

function limparDocumento(v) {
  return String(v || '').replace(/\D+/g, '');
}

function extrairValorResumoNFe(resNFe = {}) {
  const total = resNFe.vNF || resNFe.valor || resNFe.valorTotal || 0;
  const n = Number(String(total).replace(',', '.'));
  return Number.isFinite(n) ? n : 0;
}

function extrairDhEmissaoResumo(resNFe = {}) {
  return resNFe.dhEmi || resNFe.dEmi || resNFe.dataEmissao || '';
}

function extrairEmitenteResumo(resNFe = {}) {
  return resNFe.xNome || resNFe.emitente || resNFe.nomeEmitente || '';
}

function extrairCnpjEmitenteResumo(resNFe = {}) {
  return limparDocumento(resNFe.CNPJ || resNFe.CPF || resNFe.emitenteCnpj || '');
}

function montarItemDfeFromDocZip(doc) {
  const json = doc?.json || {};
  const resNFe = json?.resNFe || json?.procNFe?.NFe?.infNFe?.emit || json?.nfeProc?.NFe?.infNFe?.emit || {};
  const ide = json?.procNFe?.NFe?.infNFe?.ide || json?.nfeProc?.NFe?.infNFe?.ide || {};
  const prot = json?.procNFe?.protNFe?.infProt || json?.nfeProc?.protNFe?.infProt || {};

  return {
    nsu: String(doc?.nsu || ''),
    schema: String(doc?.schema || ''),
    tipo: doc?.schema?.includes('procNFe') ? 'xml-completo' : 'resumo',
    chave: String(resNFe.chNFe || prot.chNFe || ide.chave || ''),
    emitente: extrairEmitenteResumo(resNFe),
    emitenteCnpj: extrairCnpjEmitenteResumo(resNFe),
    dataEmissao: extrairDhEmissaoResumo(resNFe),
    valorTotal: extrairValorResumoNFe(resNFe),
    xml: String(doc?.xml || ''),
    json
  };
}

function normalizarDocsConsulta(docZip = []) {
  return (Array.isArray(docZip) ? docZip : []).map(montarItemDfeFromDocZip);
}

function removerSessoesDfeExpiradas() {
  const agora = Date.now();
  for (const [sessionId, sessao] of dfeSessions.entries()) {
    if (!sessao?.createdAt || (agora - sessao.createdAt > 1000 * 60 * 30)) {
      dfeSessions.delete(sessionId);
    }
  }
}

setInterval(removerSessoesDfeExpiradas, 1000 * 60 * 5).unref();

const uploadCertificadoDfe = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

function mapearStatusHttpPorCStat(cStat) {
  if (['472', '593', '656'].includes(String(cStat))) return 400;
  return 422;
}

function montarMensagemCStat(cStat, xMotivo, ultNSU, maxNSU) {
  const codigo = String(cStat || '');

  if (codigo === '137') {
    return `Nenhum documento localizado para este CPF/CNPJ. Use o ultNSU ${ultNSU || '000000000000000'} nas próximas consultas e aguarde ao menos 1 hora antes de consultar novamente se não houver novos documentos.`;
  }

  if (codigo === '138') {
    return xMotivo || 'Documento(s) localizado(s).';
  }

  if (codigo === '472') {
    return 'O CPF informado na consulta difere do CPF do certificado digital utilizado.';
  }

  if (codigo === '593') {
    return 'O CNPJ informado na consulta difere do CNPJ-base do certificado digital utilizado.';
  }

  if (codigo === '656') {
    return `Consumo indevido detectado pela SEFAZ. Utilize o ultNSU ${ultNSU || '000000000182444'} nas solicitações subsequentes e aguarde 1 hora antes de nova consulta.`;
  }

  return xMotivo || `Consulta rejeitada pela SEFAZ (cStat ${codigo}).`;
}

app.post('/api/dfe/consultar', uploadCertificadoDfe.single('certificado'), async (req, res) => {
  try {
    console.log('[DFE] Iniciando consulta /api/dfe/consultar');

    const senha = String(req.body?.senha || '').trim();
    const documento = limparDocumento(req.body?.documento || '');
    const cnpj = documento.length === 14 ? documento : '';
    const cpf = documento.length === 11 ? documento : '';
    const tpAmb = String(req.body?.tpAmb || '1');
    const cUFAutor = String(req.body?.cUFAutor || '29');
    const ultNSU = String(req.body?.ultNSU || '000000000000000').padStart(15, '0');
    const limiteInformado = Math.max(1, Math.min(50, Number(req.body?.limite || 15)));
    const consultaSemDocumento = !documento;
    const limiteFinal = consultaSemDocumento ? 15 : limiteInformado;

    console.log('[DFE] Parâmetros recebidos:', {
      documento,
      tipoDocumento: cnpj ? 'CNPJ' : cpf ? 'CPF' : 'VAZIO',
      tpAmb,
      cUFAutor,
      ultNSU,
      limiteInformado,
      limiteFinal,
      consultaSemDocumento,
      arquivoRecebido: !!req.file,
      nomeArquivo: req.file?.originalname || null,
      tamanhoArquivo: req.file?.size || 0
    });

    if (!req.file?.buffer) {
      console.log('[DFE] Validação falhou: certificado não enviado');
      return res.status(400).json({
        success: false,
        message: 'Selecione o certificado A1 (.pfx ou .p12) antes de consultar.'
      });
    }

    if (!senha) {
      console.log('[DFE] Validação falhou: senha não informada');
      return res.status(400).json({
        success: false,
        message: 'Informe a senha do certificado digital.'
      });
    }

    if (documento && documento.length !== 11 && documento.length !== 14) {
      console.log('[DFE] Validação falhou: documento inválido', { documento });
      return res.status(400).json({
        success: false,
        message: 'O documento informado é inválido. Informe um CPF com 11 dígitos, um CNPJ com 14 dígitos ou deixe o campo em branco.'
      });
    }

    const configDistribuicao = {
      pfx: req.file.buffer,
      passphrase: senha,
      cUFAutor,
      tpAmb
    };

    if (cnpj) configDistribuicao.cnpj = cnpj;
    if (cpf) configDistribuicao.cpf = cpf;

    console.log('[DFE] Configuração montada para DistribuicaoDFe:', {
      possuiCnpj: !!configDistribuicao.cnpj,
      possuiCpf: !!configDistribuicao.cpf,
      cnpj: configDistribuicao.cnpj || null,
      cpf: configDistribuicao.cpf || null,
      tpAmb: configDistribuicao.tpAmb,
      cUFAutor: configDistribuicao.cUFAutor
    });

    if (!configDistribuicao.cnpj && !configDistribuicao.cpf) {
      console.log('[DFE] Nenhum CPF/CNPJ informado para a consulta');
      return res.status(400).json({
        success: false,
        message: 'Informe um CPF ou CNPJ para a consulta. Se quiser aceitar vazio, implemente a extração automática do documento a partir do certificado.'
      });
    }

    console.log('[DFE] Instanciando DistribuicaoDFe...');
    const distribuicao = new DistribuicaoDFe(configDistribuicao);

    console.log('[DFE] Executando consultaUltNSU...', { ultNSU });
    const consulta = await distribuicao.consultaUltNSU(ultNSU);

    console.log('[DFE] Retorno bruto da consulta recebido:', {
      possuiError: !!consulta?.error,
      possuiData: !!consulta?.data,
      cStat: consulta?.data?.cStat || null,
      xMotivo: consulta?.data?.xMotivo || null,
      ultNSU: consulta?.data?.ultNSU || null,
      maxNSU: consulta?.data?.maxNSU || null,
      quantidadeDocZip: Array.isArray(consulta?.data?.docZip) ? consulta.data.docZip.length : 0
    });

    if (consulta?.error) {
      console.log('[DFE] Consulta retornou erro da biblioteca:', consulta.error);
      return res.status(400).json({
        success: false,
        message: `Falha no retorno da distribuição DF-e: ${consulta.error}`
      });
    }

    const data = consulta?.data || {};
    const cStat = String(data?.cStat || '');
    const xMotivo = String(data?.xMotivo || '');
    const ultNSURetorno = String(data?.ultNSU || ultNSU);
    const maxNSURetorno = String(data?.maxNSU || ultNSU);
    const documentoUsado = cnpj || cpf || '';
    const tipoDocumentoUsado = cnpj ? 'CNPJ' : cpf ? 'CPF' : '';

    if (cStat === '656') {
      console.log('[DFE] Consumo indevido detectado');
      return res.status(400).json({
        success: false,
        message: montarMensagemCStat(cStat, xMotivo, ultNSURetorno, maxNSURetorno),
        meta: {
          tpAmb: data?.tpAmb || tpAmb,
          ultNSU: ultNSURetorno,
          maxNSU: maxNSURetorno,
          cStat,
          xMotivo,
          documentoUsado,
          tipoDocumentoUsado,
          origemDocumento: documento ? 'informado' : 'certificado',
          consultaSemDocumento,
          limiteAplicado: limiteFinal
        }
      });
    }

    if (['472', '593'].includes(cStat)) {
      console.log('[DFE] Documento informado diverge do certificado', { cStat, xMotivo });
      return res.status(mapearStatusHttpPorCStat(cStat)).json({
        success: false,
        message: montarMensagemCStat(cStat, xMotivo, ultNSURetorno, maxNSURetorno),
        meta: {
          tpAmb: data?.tpAmb || tpAmb,
          ultNSU: ultNSURetorno,
          maxNSU: maxNSURetorno,
          cStat,
          xMotivo,
          documentoUsado,
          tipoDocumentoUsado,
          origemDocumento: documento ? 'informado' : 'certificado',
          consultaSemDocumento,
          limiteAplicado: limiteFinal
        }
      });
    }

    let docs = normalizarDocsConsulta(data?.docZip || []);

    console.log('[DFE] Documentos normalizados:', {
      quantidadeAntesDoSlice: docs.length,
      cStat
    });

    docs = docs.slice(0, limiteFinal);

    console.log('[DFE] Documentos após aplicar limite:', {
      quantidadeFinal: docs.length,
      limiteFinal
    });

    if (docs.length) {
      console.log('[DFE] Primeiro documento retornado:', {
        nsu: docs[0]?.nsu || null,
        chave: docs[0]?.chave || null,
        emitente: docs[0]?.emitente || null,
        tipo: docs[0]?.tipo || null,
        dataEmissao: docs[0]?.dataEmissao || null
      });
    } else {
      console.log('[DFE] Nenhum documento retornado após normalização/filtro');
    }

    const sessionId = gerarSessionIdDfe();

    dfeSessions.set(sessionId, {
      createdAt: Date.now(),
      lastAccessAt: Date.now(),
      cnpj,
      cpf,
      documentoUsado,
      documentoInformado: documento || '',
      consultaSemDocumento,
      tpAmb,
      cUFAutor,
      ultNSU: ultNSURetorno,
      maxNSU: maxNSURetorno,
      items: docs
    });

    console.log('[DFE] Sessão criada com sucesso:', {
      sessionId,
      quantidadeItens: docs.length,
      ultNSU: ultNSURetorno,
      maxNSU: maxNSURetorno,
      cStat
    });

    let msgConsulta = 'Consulta concluída com sucesso.';

    if (cStat === '138') {
      msgConsulta = consultaSemDocumento
        ? `Consulta concluída com sucesso. ${docs.length} documento(s) retornado(s) para o certificado.`
        : `Consulta concluída com sucesso. ${docs.length} documento(s) retornado(s) para o ${tipoDocumentoUsado} informado.`;
    } else if (cStat === '137') {
      msgConsulta = montarMensagemCStat(cStat, xMotivo, ultNSURetorno, maxNSURetorno);
    } else if (xMotivo) {
      msgConsulta = xMotivo;
    }

    console.log('[DFE] Finalizando rota com sucesso:', {
      sessionId,
      mensagem: msgConsulta,
      cStat
    });

    return res.json({
      success: true,
      message: msgConsulta,
      sessionId,
      items: docs.map(({ xml, json, ...rest }) => rest),
      meta: {
        tpAmb: data?.tpAmb || tpAmb,
        ultNSU: ultNSURetorno,
        maxNSU: maxNSURetorno,
        cStat,
        xMotivo,
        documentoUsado,
        tipoDocumentoUsado,
        origemDocumento: documento ? 'informado' : 'certificado',
        consultaSemDocumento,
        limiteAplicado: limiteFinal
      }
    });
  } catch (err) {
    console.error('[DFE] Erro /api/dfe/consultar:', {
      message: err?.message,
      stack: err?.stack
    });

    return res.status(500).json({
      success: false,
      message: 'Não foi possível consultar os DF-e com o certificado informado.',
      error: err.message
    });
  }
});

app.get('/api/dfe/xml/:sessionId/:nsu', async (req, res) => {
  try {
    const { sessionId, nsu } = req.params;
    const sessao = obterSessaoDfeAtiva(sessionId);

    if (!sessao) {
      return res.status(440).json({
        success: false,
        expired: true,
        message: 'Sua sessão de consulta expirou. Faça uma nova consulta para visualizar o XML.'
      });
    }

    const item = (sessao.items || []).find(x => String(x.nsu) === String(nsu));
    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'O XML solicitado não foi encontrado nesta sessão.'
      });
    }

    return res.json({
      success: true,
      xml: item.xml || ''
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: 'Erro ao recuperar o XML da nota.',
      error: err.message
    });
  }
});

app.get('/api/dfe/xml-download/:sessionId/:nsu', async (req, res) => {
  try {
    const { sessionId, nsu } = req.params;
    const sessao = obterSessaoDfeAtiva(sessionId);

    if (!sessao) {
      return res.status(440).send('Sessão expirada. Refaça a consulta para baixar o XML.');
    }

    const item = (sessao.items || []).find(x => String(x.nsu) === String(nsu));
    if (!item) {
      return res.status(404).send('Documento não encontrado na sessão atual.');
    }

    const nome = `dfe-${String(item.nsu || 'sem-nsu')}.xml`;
    res.setHeader('Content-Type', 'application/xml; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${nome}"`);
    return res.send(item.xml || '');
  } catch (err) {
    return res.status(500).send('Erro ao baixar XML.');
  }
});

app.post('/api/dfe/xml-lote', async (req, res) => {
  try {
    const sessionId = String(req.body?.sessionId || '');
    const nsus = Array.isArray(req.body?.nsus) ? req.body.nsus.map(String) : [];
    const sessao = obterSessaoDfeAtiva(sessionId);

    if (!sessao) {
      return res.status(440).json({
        success: false,
        expired: true,
        message: 'Sua sessão expirou. Refaça a consulta para gerar o ZIP.'
      });
    }

    if (!nsus.length) {
      return res.status(400).json({
        success: false,
        message: 'Selecione ao menos um documento para gerar o ZIP.'
      });
    }

    const zip = new AdmZip();

    for (const nsu of nsus) {
      const item = (sessao.items || []).find(x => String(x.nsu) === String(nsu));
      if (!item?.xml) continue;
      zip.addFile(`dfe-${nsu}.xml`, Buffer.from(item.xml, 'utf8'));
    }

    if (!zip.getEntries().length) {
      return res.status(400).json({
        success: false,
        message: 'Nenhum XML válido foi encontrado para os NSUs selecionados.'
      });
    }

    const bufferZip = zip.toBuffer();
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="dfe-selecionadas.zip"');
    return res.send(bufferZip);
  } catch (err) {
    console.error('Erro /api/dfe/xml-lote', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao gerar o arquivo ZIP das notas selecionadas.',
      error: err.message
    });
  }
});

// Equipamentos Relogio POnto

function textoLivreEquip(v, max = 255) {
  return String(v ?? '').trim().slice(0, max);
}

function validarIPv4(ip) {
  const partes = String(ip || '').trim().split('.');
  if (partes.length !== 4) return false;

  return partes.every(parte => {
    if (!/^\d+$/.test(parte)) return false;
    const n = Number(parte);
    return n >= 0 && n <= 255;
  });
}

function normalizarProtocoloEquipamento(v) {
  return String(v || '').trim().toLowerCase() === 'https' ? 'https' : 'http';
}

function normalizarTipoAfd(v) {
  return String(v || '').trim() === '1510' ? '1510' : '671';
}

function obterPortaPadraoEquipamento(protocolo) {
  return normalizarProtocoloEquipamento(protocolo) === 'https' ? 443 : 80;
}

function montarBaseUrlEquipamento({ protocolo, ip, porta }) {
  const protocoloFinal = normalizarProtocoloEquipamento(protocolo);
  const portaFinal = Number(porta) || obterPortaPadraoEquipamento(protocoloFinal);
  return `${protocoloFinal}://${ip}:${portaFinal}`;
}

function getAgentByProtocol(protocolo) {
  if (normalizarProtocoloEquipamento(protocolo) === 'https') {
    return new https.Agent({
      rejectUnauthorized: false
    });
  }

  return new http.Agent();
}

async function fetchControlIdJson(url, options = {}, protocolo = 'http') {
  const agent = getAgentByProtocol(protocolo);

  const response = await fetch(url, {
    ...options,
    agent
  });

  const contentType = response.headers.get('content-type') || '';
  let data = null;

  if (contentType.includes('application/json')) {
    data = await response.json();
  } else {
    const text = await response.text();
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }

  return { response, data };
}

async function fazerLoginControlId(equipamento) {
  const baseUrl = montarBaseUrlEquipamento(equipamento);

  const { response, data } = await fetchControlIdJson(
    `${baseUrl}/login.fcgi`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        login: equipamento.usuario,
        password: equipamento.senha
      })
    },
    equipamento.protocolo
  );

  if (!response.ok) {
    throw new Error(`Falha no login do equipamento. HTTP ${response.status}`);
  }

  if (!data?.session) {
    throw new Error('Sessão não retornada pelo equipamento.');
  }

  return {
    session: data.session,
    loginResponse: data,
    baseUrl
  };
}

async function obterAboutControlId(equipamento, session) {
  const baseUrl = montarBaseUrlEquipamento(equipamento);

  const { response, data } = await fetchControlIdJson(
    `${baseUrl}/get_about.fcgi?session=${encodeURIComponent(session)}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({})
    },
    equipamento.protocolo
  );

  if (!response.ok) {
    throw new Error(`Falha ao consultar get_about.fcgi. HTTP ${response.status}`);
  }

  return data;
}

async function obterAfdControlId(equipamento, session) {
  const baseUrl = montarBaseUrlEquipamento(equipamento);
  const mode = String(equipamento.tipoAfd) === '671' ? '&mode=671' : '';
  const url = `${baseUrl}/get_afd.fcgi?session=${encodeURIComponent(session)}${mode}`;

  const agent = getAgentByProtocol(equipamento.protocolo);

  const response = await fetch(url, {
    method: 'GET',
    agent
  });

  if (!response.ok) {
    throw new Error(`Falha ao obter AFD. HTTP ${response.status}`);
  }

  const afd = await response.text();
  return afd;
}

function mapearEquipamentoDb(row) {
  return {
    id: String(row.ID),
    codigo: row.CODIGO ?? '',
    descricao: row.DESCRICAO ?? '',
    numeroSerie: row.NUMEROSERIE ?? '',
    status: row.STATUS ?? '',
    local: row.LOCALSETOR ?? '',
    ip: row.IP ?? '',
    protocolo: normalizarProtocoloEquipamento(row.PROTOCOLO),
    porta: Number(row.PORTA) || obterPortaPadraoEquipamento(row.PROTOCOLO),
    usuario: row.USUARIO ?? '',
    senha: row.SENHA ?? '',
    tipoAfd: normalizarTipoAfd(row.TIPOAFD)
  };
}

function validarPayloadEquipamento(body = {}) {
  const payload = {
    id: String(body.id || Date.now()),
    codigo: textoLivreEquip(body.codigo, 50),
    descricao: textoLivreEquip(body.descricao, 150),
    numeroSerie: textoLivreEquip(body.numeroSerie, 100),
    status: textoLivreEquip(body.status, 30),
    local: textoLivreEquip(body.local, 150),
    ip: textoLivreEquip(body.ip, 50),
    protocolo: normalizarProtocoloEquipamento(body.protocolo),
    porta: Number(body.porta) || obterPortaPadraoEquipamento(body.protocolo),
    usuario: textoLivreEquip(body.usuario, 100),
    senha: textoLivreEquip(body.senha, 255),
    tipoAfd: normalizarTipoAfd(body.tipoAfd)
  };

  if (!payload.codigo) throw new Error('Informe o código do equipamento.');
  if (!payload.descricao) throw new Error('Informe a descrição do equipamento.');
  if (!payload.status) throw new Error('Selecione o status do equipamento.');
  if (!payload.ip) throw new Error('Informe o IP do equipamento.');
  if (!validarIPv4(payload.ip)) throw new Error('Informe um IP válido.');
  if (!payload.usuario) throw new Error('Informe o usuário do equipamento.');
  if (!payload.senha) throw new Error('Informe a senha do equipamento.');

  return payload;
}

app.get('/api/equipamentos', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD
      FROM SF_EQUIPAMENTO
      ORDER BY CREATEDAT DESC, ID DESC
    `);

    return res.json({
      success: true,
      items: rows.map(mapearEquipamentoDb)
    });
  } catch (err) {
    console.error('Erro GET /api/equipamentos', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar equipamentos.',
      error: err.message
    });
  }
});

app.get('/api/equipamentos/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do equipamento inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD
      FROM SF_EQUIPAMENTO
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: mapearEquipamentoDb(rows[0])
    });
  } catch (err) {
    console.error('Erro GET /api/equipamentos/:id', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar equipamento.',
      error: err.message
    });
  }
});


app.post('/api/equipamentos', async (req, res) => {

  console.log(req.body);
  try {
    const payload = validarPayloadEquipamento(req.body);

    const [existente] = await pool.query(
      'SELECT ID FROM SF_EQUIPAMENTO WHERE ID = ? LIMIT 1',
      [payload.id]
    );

    if (existente.length) {
      return res.status(409).json({
        success: false,
        message: 'Já existe um equipamento com esse ID.'
      });
    }

    await pool.query(`
      INSERT INTO SF_EQUIPAMENTO (
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD,
        CREATEDAT
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      payload.id,
      payload.codigo,
      payload.descricao,
      payload.numeroSerie,
      payload.status,
      payload.local,
      payload.ip,
      payload.protocolo,
      payload.porta,
      payload.usuario,
      payload.senha,
      payload.tipoAfd
    ]);


    return res.status(201).json({
      success: true,
      message: 'Equipamento cadastrado com sucesso.',
      item: payload
    });
  } catch (err) {
    console.error('Erro POST /api/equipamentos', err);
    return res.status(400).json({
      success: false,
      message: err.message || 'Erro ao cadastrar equipamento.'
    });
  }
});

app.put('/api/equipamentos/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do equipamento inválido.'
      });
    }

    const payload = validarPayloadEquipamento({
      ...req.body,
      id
    });

    const [rows] = await pool.query(
      'SELECT ID FROM SF_EQUIPAMENTO WHERE ID = ? LIMIT 1',
      [id]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    await pool.query(`
      UPDATE SF_EQUIPAMENTO
      SET
        CODIGO = ?,
        DESCRICAO = ?,
        NUMEROSERIE = ?,
        STATUS = ?,
        LOCALSETOR = ?,
        IP = ?,
        PROTOCOLO = ?,
        PORTA = ?,
        USUARIO = ?,
        SENHA = ?,
        TIPOAFD = ?,
        UPDATEDAT = NOW()
      WHERE ID = ?
    `, [
      payload.codigo,
      payload.descricao,
      payload.numeroSerie,
      payload.status,
      payload.local,
      payload.ip,
      payload.protocolo,
      payload.porta,
      payload.usuario,
      payload.senha,
      payload.tipoAfd,
      id
    ]);

    return res.json({
      success: true,
      message: 'Equipamento atualizado com sucesso.',
      item: payload
    });
  } catch (err) {
    console.error('Erro PUT /api/equipamentos/:id', err);
    return res.status(400).json({
      success: false,
      message: err.message || 'Erro ao atualizar equipamento.'
    });
  }
});

app.delete('/api/equipamentos/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do equipamento inválido.'
      });
    }

    const result = await pool.query(
      'DELETE FROM SF_EQUIPAMENTO WHERE ID = ?',
      [id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    return res.json({
      success: true,
      message: 'Equipamento removido com sucesso.'
    });
  } catch (err) {
    console.error('Erro DELETE /api/equipamentos/:id', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao remover equipamento.',
      error: err.message
    });
  }
});

app.post('/api/equipamentos/testar-comunicacao', async (req, res) => {
  try {
    console.log('--------------------------------------------------');
    console.log('[POST] /api/equipamentos/testar-comunicacao');
    console.log('[BODY RECEBIDO]', {
      ...req.body,
      senha: req.body?.senha ? '***' : ''
    });

    const payload = validarPayloadEquipamento(req.body);
    console.log('[PAYLOAD VALIDADO]', {
      ...payload,
      senha: payload?.senha ? '***' : ''
    });

    const { session, baseUrl } = await fazerLoginControlId(payload);
    console.log('[LOGIN OK]', {
      baseUrl,
      session,
      ip: payload.ip,
      protocolo: payload.protocolo,
      porta: payload.porta,
      usuario: payload.usuario,
      tipoAfd: payload.tipoAfd
    });

    let about = null;

    try {
      about = await obterAboutControlId(payload, session);
      console.log('[ABOUT OK]', about);
    } catch (errAbout) {
      console.log('[ABOUT ERRO]', errAbout.message);
      about = null;
    }

    const resposta = {
      success: true,
      message: `Comunicação realizada com sucesso via ${payload.protocolo.toUpperCase()}.`,
      session,
      baseUrl,
      equipamento: {
        ip: payload.ip,
        protocolo: payload.protocolo,
        porta: payload.porta,
        usuario: payload.usuario,
        tipoAfd: payload.tipoAfd
      },
      about
    };

    console.log('[RESPOSTA SUCESSO]', {
      ...resposta,
      session: resposta.session ? '***SESSION***' : null
    });

    return res.json(resposta);
  } catch (err) {
    console.error('Erro POST /api/equipamentos/testar-comunicacao', err);
    console.error('[STACK]', err.stack);

    return res.status(500).json({
      success: false,
      message: 'Falha na comunicação com o equipamento.',
      error: err.message
    });
  }
});

app.post('/api/equipamentos/:id/testar-comunicacao', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    const [rows] = await pool.query(`
      SELECT
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD
      FROM SF_EQUIPAMENTO
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    const equipamento = mapearEquipamentoDb(rows[0]);
    const { session, baseUrl } = await fazerLoginControlId(equipamento);

    let about = null;
    try {
      about = await obterAboutControlId(equipamento, session);
    } catch (errAbout) {
      about = null;
    }

    return res.json({
      success: true,
      message: `Comunicação realizada com sucesso via ${equipamento.protocolo.toUpperCase()}.`,
      session,
      baseUrl,
      equipamento,
      about
    });
  } catch (err) {
    console.error('Erro POST /api/equipamentos/:id/testar-comunicacao', err);
    return res.status(500).json({
      success: false,
      message: 'Falha na comunicação com o equipamento.',
      error: err.message
    });
  }
});

app.get('/api/equipamentos/:id/about', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();

    const [rows] = await pool.query(`
      SELECT
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD
      FROM SF_EQUIPAMENTO
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    const equipamento = mapearEquipamentoDb(rows[0]);
    const { session } = await fazerLoginControlId(equipamento);
    const about = await obterAboutControlId(equipamento, session);

    return res.json({
      success: true,
      about
    });
  } catch (err) {
    console.error('Erro GET /api/equipamentos/:id/about', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao consultar informações do equipamento.',
      error: err.message
    });
  }
});

app.get('/api/equipamentos/:id/afd', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();

    const [rows] = await pool.query(`
      SELECT
        ID,
        CODIGO,
        DESCRICAO,
        NUMEROSERIE,
        STATUS,
        LOCALSETOR,
        IP,
        PROTOCOLO,
        PORTA,
        USUARIO,
        SENHA,
        TIPOAFD
      FROM SF_EQUIPAMENTO
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Equipamento não encontrado.'
      });
    }

    const equipamento = mapearEquipamentoDb(rows[0]);
    const { session } = await fazerLoginControlId(equipamento);
    const afd = await obterAfdControlId(equipamento, session);

    const nomeArquivo = `afd-${equipamento.codigo || equipamento.id}-${equipamento.tipoAfd}.txt`;

    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${nomeArquivo}"`);

    return res.send(afd);
  } catch (err) {
    console.error('Erro GET /api/equipamentos/:id/afd', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao exportar AFD do equipamento.',
      error: err.message
    });
  }
});

// ===============================
// CADASTRO DE CALENDÁRIOS
// ===============================

app.get('/api/calendarios', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        ID,
        UNIDADETRABALHO,
        PERIODO,
        TIPOPERIODO,
        TIPORECORRENCIA,
        DATE_FORMAT(DATAINICIAL, '%Y-%m-%d') AS DATAINICIAL,
        DATE_FORMAT(DATAFINAL, '%Y-%m-%d') AS DATAFINAL,
        REPETETODOANO,
        DATE_FORMAT(DATAINICIALTROCA, '%Y-%m-%d') AS DATAINICIALTROCA,
        DATE_FORMAT(DATAFINALTROCA, '%Y-%m-%d') AS DATAFINALTROCA,
        DATE_FORMAT(NOVADATAINICIAL, '%Y-%m-%d') AS NOVADATAINICIAL,
        DATE_FORMAT(NOVADATAFINAL, '%Y-%m-%d') AS NOVADATAFINAL,
        TIME_FORMAT(HORAINICIO, '%H:%i') AS HORAINICIO,
        TIME_FORMAT(HORAFIM, '%H:%i') AS HORAFIM,
        STATUS,
        USUARIOCADASTRO,
        USUARIOALTERACAO,
        OBSERVACAO,
        DATACADASTRO,
        DATAALTERACAO
      FROM SF_CALENDARIO
      ORDER BY ID DESC
    `);

    return res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    console.error('Erro ao listar calendários:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao listar calendários.',
      error: err.message
    });
  }
});

app.get('/api/calendarios/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [rows] = await pool.query(`
      SELECT
        ID,
        UNIDADETRABALHO,
        PERIODO,
        TIPOPERIODO,
        TIPORECORRENCIA,
        DATE_FORMAT(DATAINICIAL, '%Y-%m-%d') AS DATAINICIAL,
        DATE_FORMAT(DATAFINAL, '%Y-%m-%d') AS DATAFINAL,
        REPETETODOANO,
        DATE_FORMAT(DATAINICIALTROCA, '%Y-%m-%d') AS DATAINICIALTROCA,
        DATE_FORMAT(DATAFINALTROCA, '%Y-%m-%d') AS DATAFINALTROCA,
        DATE_FORMAT(NOVADATAINICIAL, '%Y-%m-%d') AS NOVADATAINICIAL,
        DATE_FORMAT(NOVADATAFINAL, '%Y-%m-%d') AS NOVADATAFINAL,
        TIME_FORMAT(HORAINICIO, '%H:%i') AS HORAINICIO,
        TIME_FORMAT(HORAFIM, '%H:%i') AS HORAFIM,
        STATUS,
        USUARIOCADASTRO,
        USUARIOALTERACAO,
        OBSERVACAO,
        DATACADASTRO,
        DATAALTERACAO
      FROM SF_CALENDARIO
      WHERE ID = ?
      LIMIT 1
    `, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Calendário não encontrado.'
      });
    }

    return res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    console.error('Erro ao buscar calendário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao buscar calendário.',
      error: err.message
    });
  }
});

app.post('/api/calendarios', async (req, res) => {
  try {
    const unidadeTrabalho = String(req.body?.unidadeTrabalho ?? '').trim();
    const periodo = String(req.body?.periodo ?? '').trim();
    const tipoPeriodo = String(req.body?.tipoPeriodo ?? '').trim().toLowerCase();
    const tipoRecorrencia = String(req.body?.tipoRecorrencia ?? 'UNICO').trim().toUpperCase();
    const dataInicial = String(req.body?.dataInicial ?? '').trim();
    const dataFinalRaw = String(req.body?.dataFinal ?? '').trim();
    const repeteTodoAno = String(req.body?.repeteTodoAno ?? 'N').trim().toUpperCase();
    const dataInicialTroca = String(req.body?.dataInicialTroca ?? '').trim();
    const dataFinalTroca = String(req.body?.dataFinalTroca ?? '').trim();
    const novaDataInicial = String(req.body?.novaDataInicial ?? '').trim();
    const novaDataFinal = String(req.body?.novaDataFinal ?? '').trim();
    const horaInicio = String(req.body?.horaInicio ?? '').trim();
    const horaFim = String(req.body?.horaFim ?? '').trim();
    const status = String(req.body?.status ?? 'Ativo').trim() || 'Ativo';
    const usuario = String(req.body?.usuario ?? '').trim() || 'SISTEMA';
    const observacao = String(req.body?.observacao ?? '').trim();

    const dataFinal = tipoPeriodo === 'intervalo' ? dataFinalRaw : null;

    if (!unidadeTrabalho) {
      return res.status(400).json({
        success: false,
        message: 'Informe a unidade de trabalho.'
      });
    }

    if (!tipoPeriodo || !['data', 'intervalo'].includes(tipoPeriodo)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um tipo de período válido.'
      });
    }

    if (!['UNICO', 'ANUAL', 'TROCA_FERIADO'].includes(tipoRecorrencia)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um tipo de recorrência válido.'
      });
    }

    if (!periodo) {
      return res.status(400).json({
        success: false,
        message: 'Informe o período.'
      });
    }

    if (!horaInicio) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de início.'
      });
    }

    if (!horaFim) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de fim.'
      });
    }

    if (tipoRecorrencia === 'TROCA_FERIADO') {
      if (!dataInicialTroca || !dataFinalTroca) {
        return res.status(400).json({
          success: false,
          message: 'Informe o período original do feriado.'
        });
      }

      if (!novaDataInicial || !novaDataFinal) {
        return res.status(400).json({
          success: false,
          message: 'Informe o novo período da troca.'
        });
      }

      if (dataFinalTroca < dataInicialTroca) {
        return res.status(400).json({
          success: false,
          message: 'A data final do feriado não pode ser menor que a inicial.'
        });
      }

      if (novaDataFinal < novaDataInicial) {
        return res.status(400).json({
          success: false,
          message: 'A nova data final não pode ser menor que a nova data inicial.'
        });
      }
    } else {
      if (!dataInicial) {
        return res.status(400).json({
          success: false,
          message: 'Informe a data inicial.'
        });
      }

      if (tipoPeriodo === 'intervalo' && !dataFinal) {
        return res.status(400).json({
          success: false,
          message: 'Informe a data final.'
        });
      }

      if (tipoPeriodo === 'intervalo' && dataFinal < dataInicial) {
        return res.status(400).json({
          success: false,
          message: 'A data final não pode ser menor que a data inicial.'
        });
      }
    }

    const [result] = await pool.query(`
      INSERT INTO SF_CALENDARIO (
        UNIDADETRABALHO,
        PERIODO,
        TIPOPERIODO,
        TIPORECORRENCIA,
        DATAINICIAL,
        DATAFINAL,
        REPETETODOANO,
        DATAINICIALTROCA,
        DATAFINALTROCA,
        NOVADATAINICIAL,
        NOVADATAFINAL,
        HORAINICIO,
        HORAFIM,
        STATUS,
        USUARIOCADASTRO,
        OBSERVACAO,
        DATACADASTRO
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [
      unidadeTrabalho,
      periodo,
      tipoPeriodo,
      tipoRecorrencia,
      dataInicial || null,
      dataFinal,
      tipoRecorrencia === 'ANUAL' ? 'S' : 'N',
      dataInicialTroca || null,
      dataFinalTroca || null,
      novaDataInicial || null,
      novaDataFinal || null,
      horaInicio,
      horaFim,
      status,
      usuario,
      observacao || null
    ]);

    return res.status(201).json({
      success: true,
      id: result.insertId,
      message: 'Calendário cadastrado com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao cadastrar calendário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar calendário.',
      error: err.message
    });
  }
});

app.put('/api/calendarios/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const unidadeTrabalho = String(req.body?.unidadeTrabalho ?? '').trim();
    const periodo = String(req.body?.periodo ?? '').trim();
    const tipoPeriodo = String(req.body?.tipoPeriodo ?? '').trim().toLowerCase();
    const tipoRecorrencia = String(req.body?.tipoRecorrencia ?? 'UNICO').trim().toUpperCase();
    const dataInicial = String(req.body?.dataInicial ?? '').trim();
    const dataFinalRaw = String(req.body?.dataFinal ?? '').trim();
    const repeteTodoAno = String(req.body?.repeteTodoAno ?? 'N').trim().toUpperCase();
    const dataInicialTroca = String(req.body?.dataInicialTroca ?? '').trim();
    const dataFinalTroca = String(req.body?.dataFinalTroca ?? '').trim();
    const novaDataInicial = String(req.body?.novaDataInicial ?? '').trim();
    const novaDataFinal = String(req.body?.novaDataFinal ?? '').trim();
    const horaInicio = String(req.body?.horaInicio ?? '').trim();
    const horaFim = String(req.body?.horaFim ?? '').trim();
    const status = String(req.body?.status ?? '').trim() || 'Ativo';
    const usuario = String(req.body?.usuario ?? '').trim() || 'SISTEMA';
    const observacao = String(req.body?.observacao ?? '').trim();

    const dataFinal = tipoPeriodo === 'intervalo' ? dataFinalRaw : null;

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    if (!unidadeTrabalho) {
      return res.status(400).json({
        success: false,
        message: 'Informe a unidade de trabalho.'
      });
    }

    if (!tipoPeriodo || !['data', 'intervalo'].includes(tipoPeriodo)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um tipo de período válido.'
      });
    }

    if (!['UNICO', 'ANUAL', 'TROCA_FERIADO'].includes(tipoRecorrencia)) {
      return res.status(400).json({
        success: false,
        message: 'Informe um tipo de recorrência válido.'
      });
    }

    if (!periodo) {
      return res.status(400).json({
        success: false,
        message: 'Informe o período.'
      });
    }

    if (!horaInicio) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de início.'
      });
    }

    if (!horaFim) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de fim.'
      });
    }

    if (tipoRecorrencia === 'TROCA_FERIADO') {
      if (!dataInicialTroca || !dataFinalTroca) {
        return res.status(400).json({
          success: false,
          message: 'Informe o período original do feriado.'
        });
      }

      if (!novaDataInicial || !novaDataFinal) {
        return res.status(400).json({
          success: false,
          message: 'Informe o novo período da troca.'
        });
      }

      if (dataFinalTroca < dataInicialTroca) {
        return res.status(400).json({
          success: false,
          message: 'A data final do feriado não pode ser menor que a inicial.'
        });
      }

      if (novaDataFinal < novaDataInicial) {
        return res.status(400).json({
          success: false,
          message: 'A nova data final não pode ser menor que a nova data inicial.'
        });
      }
    } else {
      if (!dataInicial) {
        return res.status(400).json({
          success: false,
          message: 'Informe a data inicial.'
        });
      }

      if (tipoPeriodo === 'intervalo' && !dataFinal) {
        return res.status(400).json({
          success: false,
          message: 'Informe a data final.'
        });
      }

      if (tipoPeriodo === 'intervalo' && dataFinal < dataInicial) {
        return res.status(400).json({
          success: false,
          message: 'A data final não pode ser menor que a data inicial.'
        });
      }
    }

    const [result] = await pool.query(`
      UPDATE SF_CALENDARIO
      SET
        UNIDADETRABALHO = ?,
        PERIODO = ?,
        TIPOPERIODO = ?,
        TIPORECORRENCIA = ?,
        DATAINICIAL = ?,
        DATAFINAL = ?,
        REPETETODOANO = ?,
        DATAINICIALTROCA = ?,
        DATAFINALTROCA = ?,
        NOVADATAINICIAL = ?,
        NOVADATAFINAL = ?,
        HORAINICIO = ?,
        HORAFIM = ?,
        STATUS = ?,
        USUARIOALTERACAO = ?,
        OBSERVACAO = ?,
        DATAALTERACAO = NOW()
      WHERE ID = ?
    `, [
      unidadeTrabalho,
      periodo,
      tipoPeriodo,
      tipoRecorrencia,
      dataInicial || null,
      dataFinal,
      tipoRecorrencia === 'ANUAL' ? 'S' : 'N',
      dataInicialTroca || null,
      dataFinalTroca || null,
      novaDataInicial || null,
      novaDataFinal || null,
      horaInicio,
      horaFim,
      status,
      usuario,
      observacao || null,
      id
    ]);

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Calendário não encontrado.'
      });
    }

    return res.json({
      success: true,
      message: 'Calendário atualizado com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao atualizar calendário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao atualizar calendário.',
      error: err.message
    });
  }
});

app.delete('/api/calendarios/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID inválido.'
      });
    }

    const [result] = await pool.query(`
      DELETE FROM SF_CALENDARIO
      WHERE ID = ?
    `, [id]);

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Calendário não encontrado.'
      });
    }

    return res.json({
      success: true,
      message: 'Calendário excluído com sucesso.'
    });
  } catch (err) {
    console.error('Erro ao excluir calendário:', err);
    return res.status(500).json({
      success: false,
      message: 'Erro ao excluir calendário.',
      error: err.message
    });
  }
});

// ======================================================
// Jornada de Trabalho
// ======================================================

// =========================
// JORNADAS DE TRABALHO
// =========================

// Helpers locais caso não existam no seu projeto
function texto(v) {
  if (v === undefined || v === null) return '';
  return String(v).trim();
}

function numero(v, padrao = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : padrao;
}

function dataOuNull(v) {
  const s = texto(v);
  return s || null;
}

function horaOuNull(v) {
  const s = texto(v);
  return s || null;
}

// GET /api/jornadas
app.get('/api/jornadas', async (req, res) => {
  try {
    const busca = texto(req.query?.q);

    let sql = `
      SELECT
        ID,
        DESCRICAO,
        HORA_ENTRADA,
        HORA_SAIDA,
        INTERVALO_MINUTOS,
        CARGA_HORARIA,
        TOLERANCIA_ATRASO_MIN,
        TOLERANCIA_EXTRA_MIN,
        STATUS,
        OBSERVACAO,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_JORNADA_TRABALHO
    `;

    const params = [];

    if (busca) {
      const like = `%${busca}%`;
      sql += `
        WHERE
          DESCRICAO LIKE ?
          OR HORA_ENTRADA LIKE ?
          OR HORA_SAIDA LIKE ?
          OR STATUS LIKE ?
          OR CARGA_HORARIA LIKE ?
      `;
      params.push(like, like, like, like, like);
    }

    sql += ` ORDER BY DESCRICAO ASC, ID DESC`;

    const [rows] = await pool.query(sql, params);

    res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar jornadas.',
      error: err.message
    });
  }
});

// GET /api/jornadas/:id
app.get('/api/jornadas/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);

    const sql = `
      SELECT
        ID,
        DESCRICAO,
        HORA_ENTRADA,
        HORA_SAIDA,
        INTERVALO_MINUTOS,
        CARGA_HORARIA,
        TOLERANCIA_ATRASO_MIN,
        TOLERANCIA_EXTRA_MIN,
        STATUS,
        OBSERVACAO,
        CRIADO_EM,
        ATUALIZADO_EM
      FROM SF_JORNADA_TRABALHO
      WHERE ID = ?
      LIMIT 1
    `;

    const [rows] = await pool.query(sql, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Jornada não encontrada.'
      });
    }

    res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao buscar jornada.',
      error: err.message
    });
  }
});

// POST /api/jornadas
app.post('/api/jornadas', async (req, res) => {
  try {
    const descricao = texto(req.body?.descricao);
    const horaEntrada = horaOuNull(req.body?.horaEntrada);
    const horaSaida = horaOuNull(req.body?.horaSaida);
    const intervaloMinutos = numero(req.body?.intervaloMinutos, 0);
    const cargaHoraria = texto(req.body?.cargaHoraria);
    const toleranciaAtrasoMin = numero(req.body?.toleranciaAtrasoMin, 0);
    const toleranciaExtraMin = numero(req.body?.toleranciaExtraMin, 0);
    const status = texto(req.body?.status || 'ATIVO');
    const observacao = texto(req.body?.observacao);

    if (!descricao) {
      return res.status(400).json({
        success: false,
        message: 'Informe a descrição da jornada.'
      });
    }

    if (!horaEntrada || !horaSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de entrada e a hora de saída.'
      });
    }

    const sql = `
      INSERT INTO SF_JORNADA_TRABALHO (
        DESCRICAO,
        HORA_ENTRADA,
        HORA_SAIDA,
        INTERVALO_MINUTOS,
        CARGA_HORARIA,
        TOLERANCIA_ATRASO_MIN,
        TOLERANCIA_EXTRA_MIN,
        STATUS,
        OBSERVACAO
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      descricao,
      horaEntrada,
      horaSaida,
      intervaloMinutos,
      cargaHoraria || null,
      toleranciaAtrasoMin,
      toleranciaExtraMin,
      status || 'ATIVO',
      observacao || null
    ];

    const [result] = await pool.query(sql, params);

    res.json({
      success: true,
      message: 'Jornada cadastrada com sucesso.',
      id: result.insertId
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao cadastrar jornada.',
      error: err.message
    });
  }
});

// PUT /api/jornadas/:id
app.put('/api/jornadas/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);

    const descricao = texto(req.body?.descricao);
    const horaEntrada = horaOuNull(req.body?.horaEntrada);
    const horaSaida = horaOuNull(req.body?.horaSaida);
    const intervaloMinutos = numero(req.body?.intervaloMinutos, 0);
    const cargaHoraria = texto(req.body?.cargaHoraria);
    const toleranciaAtrasoMin = numero(req.body?.toleranciaAtrasoMin, 0);
    const toleranciaExtraMin = numero(req.body?.toleranciaExtraMin, 0);
    const status = texto(req.body?.status || 'ATIVO');
    const observacao = texto(req.body?.observacao);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID da jornada inválido.'
      });
    }

    if (!descricao) {
      return res.status(400).json({
        success: false,
        message: 'Informe a descrição da jornada.'
      });
    }

    if (!horaEntrada || !horaSaida) {
      return res.status(400).json({
        success: false,
        message: 'Informe a hora de entrada e a hora de saída.'
      });
    }

    const [exists] = await pool.query(
      `SELECT ID FROM SF_JORNADA_TRABALHO WHERE ID = ? LIMIT 1`,
      [id]
    );

    if (!exists.length) {
      return res.status(404).json({
        success: false,
        message: 'Jornada não encontrada.'
      });
    }

    const sql = `
      UPDATE SF_JORNADA_TRABALHO
      SET
        DESCRICAO = ?,
        HORA_ENTRADA = ?,
        HORA_SAIDA = ?,
        INTERVALO_MINUTOS = ?,
        CARGA_HORARIA = ?,
        TOLERANCIA_ATRASO_MIN = ?,
        TOLERANCIA_EXTRA_MIN = ?,
        STATUS = ?,
        OBSERVACAO = ?
      WHERE ID = ?
    `;

    const params = [
      descricao,
      horaEntrada,
      horaSaida,
      intervaloMinutos,
      cargaHoraria || null,
      toleranciaAtrasoMin,
      toleranciaExtraMin,
      status || 'ATIVO',
      observacao || null,
      id
    ];

    await pool.query(sql, params);

    res.json({
      success: true,
      message: 'Jornada atualizada com sucesso.'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar jornada.',
      error: err.message
    });
  }
});

// DELETE /api/jornadas/:id
app.delete('/api/jornadas/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID da jornada inválido.'
      });
    }

    const [vinculos] = await pool.query(
      `SELECT ID FROM SF_USUARIO_JORNADA WHERE JORNADA_ID = ? AND STATUS = 'ATIVO' LIMIT 1`,
      [id]
    );

    if (vinculos.length) {
      return res.status(400).json({
        success: false,
        message: 'Não é possível excluir a jornada porque existem usuários vinculados.'
      });
    }

    const [result] = await pool.query(
      `DELETE FROM SF_JORNADA_TRABALHO WHERE ID = ?`,
      [id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Jornada não encontrada.'
      });
    }

    res.json({
      success: true,
      message: 'Jornada removida com sucesso.'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao excluir jornada.',
      error: err.message
    });
  }
});

// GET /api/jornadas/:id/vinculos
app.get('/api/jornadas/:id/vinculos', async (req, res) => {
  try {
    const jornadaId = numero(req.params.id);

    const sql = `
      SELECT
        J.ID,
        J.USUARIO_ID,
        J.JORNADA_ID,
        J.DATA_INICIO,
        J.DATA_FIM,
        J.STATUS,
        J.CRIADO_EM,
        J.ATUALIZADO_EM,
        U.nome AS USUARIO_NOME,
        U.EMAIL AS USUARIO_EMAIL,
        U.perfil AS USUARIO_PERFIL,
        U.setor AS USUARIO_SETOR,
        JT.DESCRICAO AS JORNADA_DESCRICAO,
        JT.HORA_ENTRADA,
        JT.HORA_SAIDA
      FROM SF_USUARIO_JORNADA J
      INNER JOIN SF_USUARIO U ON U.id = J.USUARIO_ID
      INNER JOIN SF_JORNADA_TRABALHO JT ON JT.ID = J.JORNADA_ID
      WHERE J.JORNADA_ID = ?
      ORDER BY U.nome ASC, J.DATA_INICIO DESC
    `;

    const [rows] = await pool.query(sql, [jornadaId]);

    res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar vínculos da jornada.',
      error: err.message
    });
  }
});

// GET /api/jornadas/vinculos
app.get('/api/jornadas-vinculos', async (req, res) => {
  try {
    const busca = texto(req.query?.q);

    let sql = `
      SELECT
        J.ID,
        J.USUARIO_ID,
        J.JORNADA_ID,
        J.DATA_INICIO,
        J.DATA_FIM,
        J.STATUS,
        U.nome AS USUARIO_NOME,
        U.EMAIL AS USUARIO_EMAIL,
        U.perfil AS USUARIO_PERFIL,
        U.setor AS USUARIO_SETOR,
        JT.DESCRICAO AS JORNADA_DESCRICAO,
        JT.HORA_ENTRADA,
        JT.HORA_SAIDA
      FROM SF_USUARIO_JORNADA J
      INNER JOIN SF_USUARIO U ON U.id = J.USUARIO_ID
      INNER JOIN SF_JORNADA_TRABALHO JT ON JT.ID = J.JORNADA_ID
    `;

    const params = [];

    if (busca) {
      const like = `%${busca}%`;
      sql += `
        WHERE
          U.nome LIKE ?
          OR U.EMAIL LIKE ?
          OR U.perfil LIKE ?
          OR U.setor LIKE ?
          OR JT.DESCRICAO LIKE ?
          OR J.STATUS LIKE ?
      `;
      params.push(like, like, like, like, like, like);
    }

    sql += ` ORDER BY U.nome ASC, J.DATA_INICIO DESC`;

    const [rows] = await pool.query(sql, params);

    res.json({
      success: true,
      items: rows
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao listar vínculos de jornadas.',
      error: err.message
    });
  }
});

// GET /api/jornadas/vinculos/:id
app.get('/api/jornadas/vinculos/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);

    const sql = `
      SELECT
        J.ID,
        J.USUARIO_ID,
        J.JORNADA_ID,
        J.DATA_INICIO,
        J.DATA_FIM,
        J.STATUS,
        U.nome AS USUARIO_NOME,
        U.EMAIL AS USUARIO_EMAIL,
        JT.DESCRICAO AS JORNADA_DESCRICAO
      FROM SF_USUARIO_JORNADA J
      INNER JOIN SF_USUARIO U ON U.id = J.USUARIO_ID
      INNER JOIN SF_JORNADA_TRABALHO JT ON JT.ID = J.JORNADA_ID
      WHERE J.ID = ?
      LIMIT 1
    `;

    const [rows] = await pool.query(sql, [id]);

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    res.json({
      success: true,
      item: rows[0]
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao buscar vínculo.',
      error: err.message
    });
  }
});

// POST /api/jornadas/vincular-usuario
app.post('/api/jornadas/vincular-usuario', async (req, res) => {
  try {
    const usuarioId = Number(req.body?.usuarioId);
    const jornadaId = Number(req.body?.jornadaId);
    const dataInicio = dataOuNull(req.body?.dataInicio);
    const dataFim = dataOuNull(req.body?.dataFim);
    const status = texto(req.body?.status || 'ATIVO');

    if (!usuarioId || !jornadaId || !dataInicio) {
      return res.status(400).json({
        success: false,
        message: 'Usuário, jornada e data de início são obrigatórios.'
      });
    }

    const [usuarioRows] = await pool.query(
      `SELECT id, nome FROM SF_USUARIO WHERE id = ? LIMIT 1`,
      [usuarioId]
    );

    if (!usuarioRows.length) {
      return res.status(404).json({
        success: false,
        message: 'Usuário não encontrado.'
      });
    }

    const [jornadaRows] = await pool.query(
      `SELECT ID, DESCRICAO FROM SF_JORNADA_TRABALHO WHERE ID = ? LIMIT 1`,
      [jornadaId]
    );

    if (!jornadaRows.length) {
      return res.status(404).json({
        success: false,
        message: 'Jornada não encontrada.'
      });
    }

    const [duplicado] = await pool.query(
      `
        SELECT ID
        FROM SF_USUARIO_JORNADA
        WHERE USUARIO_ID = ?
          AND JORNADA_ID = ?
          AND DATA_INICIO = ?
        LIMIT 1
      `,
      [usuarioId, jornadaId, dataInicio]
    );

    if (duplicado.length) {
      return res.status(400).json({
        success: false,
        message: 'Já existe vínculo deste usuário com esta jornada nesta data.'
      });
    }

    const sql = `
      INSERT INTO SF_USUARIO_JORNADA (
        USUARIO_ID,
        JORNADA_ID,
        DATA_INICIO,
        DATA_FIM,
        STATUS
      ) VALUES (?, ?, ?, ?, ?)
    `;

    const params = [
      usuarioId,
      jornadaId,
      dataInicio,
      dataFim || null,
      status || 'ATIVO'
    ];

    const [result] = await pool.query(sql, params);

    res.json({
      success: true,
      message: 'Usuário vinculado à jornada com sucesso.',
      id: result.insertId
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao vincular usuário à jornada.',
      error: err.message
    });
  }
});

// PUT /api/jornadas/vinculos/:id
app.put('/api/jornadas/vinculos/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);
    const usuarioId = Number(req.body?.usuarioId);
    const jornadaId = Number(req.body?.jornadaId);
    const dataInicio = dataOuNull(req.body?.dataInicio);
    const dataFim = dataOuNull(req.body?.dataFim);
    const status = texto(req.body?.status || 'ATIVO');

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do vínculo inválido.'
      });
    }

    if (!usuarioId || !jornadaId || !dataInicio) {
      return res.status(400).json({
        success: false,
        message: 'Usuário, jornada e data de início são obrigatórios.'
      });
    }

    const [exists] = await pool.query(
      `SELECT ID FROM SF_USUARIO_JORNADA WHERE ID = ? LIMIT 1`,
      [id]
    );

    if (!exists.length) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    const [duplicado] = await pool.query(
      `
        SELECT ID
        FROM SF_USUARIO_JORNADA
        WHERE USUARIO_ID = ?
          AND JORNADA_ID = ?
          AND DATA_INICIO = ?
          AND ID <> ?
        LIMIT 1
      `,
      [usuarioId, jornadaId, dataInicio, id]
    );

    if (duplicado.length) {
      return res.status(400).json({
        success: false,
        message: 'Já existe outro vínculo igual para este usuário.'
      });
    }

    const sql = `
      UPDATE SF_USUARIO_JORNADA
      SET
        USUARIO_ID = ?,
        JORNADA_ID = ?,
        DATA_INICIO = ?,
        DATA_FIM = ?,
        STATUS = ?
      WHERE ID = ?
    `;

    const params = [
      usuarioId,
      jornadaId,
      dataInicio,
      dataFim || null,
      status || 'ATIVO',
      id
    ];

    await pool.query(sql, params);

    res.json({
      success: true,
      message: 'Vínculo atualizado com sucesso.'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao atualizar vínculo.',
      error: err.message
    });
  }
});

// DELETE /api/jornadas/vinculos/:id
app.delete('/api/jornadas/vinculos/:id', async (req, res) => {
  try {
    const id = numero(req.params.id);

    if (!id) {
      return res.status(400).json({
        success: false,
        message: 'ID do vínculo inválido.'
      });
    }

    const [result] = await pool.query(
      `DELETE FROM SF_USUARIO_JORNADA WHERE ID = ?`,
      [id]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: 'Vínculo não encontrado.'
      });
    }

    res.json({
      success: true,
      message: 'Vínculo removido com sucesso.'
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: 'Erro ao excluir vínculo.',
      error: err.message
    });
  }
});

// =====================
// Inicia servidor (sempre por último)
// =====================
app.listen(PORT, () => {
  console.log(`🚀 API rodando na porta ${PORT}`);
  console.log('✅ Teste: /health');
});

