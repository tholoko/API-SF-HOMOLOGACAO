let {
    DistribuicaoHelper,
    RetornoHelper
} = require("../helpers");

class DistribuicaoController {
    static async enviar(e) {
        var r = DistribuicaoHelper.montarRequest(e), e = await DistribuicaoHelper.enviarConsulta(r, e), t = await DistribuicaoHelper.montarResponse(e.data);
        return RetornoHelper.montarRetorno({
            json: t,
            data: r,
            retornoSefaz: e
        });
    }
}

module.exports = Object.freeze(DistribuicaoController);