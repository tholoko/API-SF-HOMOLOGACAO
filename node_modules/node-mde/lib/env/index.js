let CA = require("./ca").CA, DISTRIBUICAO = require("./distribuicao").DISTRIBUICAO, EVENTOS = require("./evento").EVENTOS, RECEPCAO = require("./recepcao").RECEPCAO, CODIGOS_UF = require("./uf").CODIGOS_UF, VERSION = require("./version").VERSION, ZONES = require("./zone").ZONES;

module.exports = {
    CA: CA,
    CODIGOS_UF: CODIGOS_UF,
    DISTRIBUICAO: DISTRIBUICAO,
    EVENTOS: EVENTOS,
    RECEPCAO: RECEPCAO,
    VERSION: VERSION,
    ZONES: ZONES
};