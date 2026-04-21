export = schema;
declare const schema: Readonly<{
    DistribuicaoSchema: {
        new (): {};
        montarSchema(options: any): {
            nfeDistDFeInteresse: {
                nfeDadosMsg: {
                    distDFeInt: {
                        tpAmb: any;
                        cUFAutor: any;
                    };
                };
                '@_xmlns': string;
            };
        };
    };
    RecepcaoSchema: {
        new (): {};
        montarSchema(options: any): {
            nfeDadosMsg: {
                envEvento: {
                    idLote: any;
                    evento: {
                        infEvento: {
                            cOrgao: any;
                            tpAmb: any;
                        };
                        '@_versao': string;
                    };
                    '@_xmlns': string;
                    '@_versao': string;
                };
                '@_xmlns': string;
            };
        };
    };
}>;
