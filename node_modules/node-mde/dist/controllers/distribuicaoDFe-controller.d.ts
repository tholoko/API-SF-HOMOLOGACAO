declare const _exports: typeof DistribuicaoController;
export = _exports;
declare class DistribuicaoController {
    /**
     *
     * @param {Object} opts
     * @returns {Promise<{data:{tpAmb: string,verAplic: string,cStat: string,xMotivo: string,dhResp: string,ultNSU: string,maxNSU: string, docZip:[{xml: string,json: Object,nsu: string,schema: string}]}, error: string, reqXml: string, resXml: string, status: number}>}
     */
    static enviar(opts: any): Promise<{
        data: {
            tpAmb: string;
            verAplic: string;
            cStat: string;
            xMotivo: string;
            dhResp: string;
            ultNSU: string;
            maxNSU: string;
            docZip: [{
                xml: string;
                json: any;
                nsu: string;
                schema: string;
            }];
        };
        error: string;
        reqXml: string;
        resXml: string;
        status: number;
    }>;
}
