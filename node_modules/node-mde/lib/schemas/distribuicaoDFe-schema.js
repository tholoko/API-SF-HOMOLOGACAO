class DistribuicaoSchema {
    static montarSchema(t) {
        var e = {
            tpAmb: t.tpAmb,
            cUFAutor: t.cUFAutor
        };
        return t.cnpj ? e.CNPJ = t.cnpj : e.CPF = t.cpf, t.ultNSU ? e.distNSU = {
            ultNSU: t.ultNSU
        } : t.chNFe ? e.consChNFe = {
            chNFe: t.chNFe
        } : e.consNSU = {
            NSU: t.nsu
        }, e["@_xmlns"] = "http://www.portalfiscal.inf.br/nfe", e["@_versao"] = "1.01", 
        {
            nfeDistDFeInteresse: {
                nfeDadosMsg: {
                    distDFeInt: e
                },
                "@_xmlns": "http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe"
            }
        };
    }
}

module.exports = Object.freeze(DistribuicaoSchema);