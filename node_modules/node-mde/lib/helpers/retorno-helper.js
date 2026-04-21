class RetornoHelper {
    static montarRetorno(r) {
        var {
            json: r,
            data: e,
            retornoSefaz: t
        } = r, e = {
            data: r,
            reqXml: e,
            resXml: t.data,
            status: t.status
        };
        return r.error && (e.data = {}, e.error = r.error), 2 < Math.floor(t.status / 100) && !r.error && (e.data = {}, 
        e.error = t.data), e;
    }
}

module.exports = Object.freeze(RetornoHelper);