import _ from 'lodash';
import 'isomorphic-fetch';

export function makeRequest(url, method, payload){
    const { hostname, port, protocol } = window.location;

    let fetchOptions = {
        method: method,
        headers: {}
    };

    let finalUrl = `${protocol}//${hostname}:${port}/72/iapi/${url}`;
   
    if(payload) {
        // Add headers.
        if(payload.header_variables) {
            fetchOptions.headers = payload.header_variables;
        }

        // Add missing headers.
        if(!fetchOptions.headers['Accept']) {
            fetchOptions.headers['Accept'] = 'application/json';
        } else if (!fetchOptions.headers['Accept'].contains('application/json')) {
            fetchOptions.headers['Accept'] += ', ' + 'application/json';
        }

         // Add the body variables.
        if(payload.body_variables) {
            if(payload.body_variables instanceof FormData) {
                fetchOptions.body = payload.body_variables;
            } else if(Object.keys(payload.body_variables).length > 0) {
                fetchOptions['Content-Type'] = 'application/json;charset=UTF-8';
                fetchOptions.body = JSON.stringify(payload.body_variables);
            }
        }

        // Add the path variables.
        if(payload.path_variables && Object.keys(payload.path_variables).length > 0) {
            for (const [field, value] of Object.entries(payload.path_variables)) {
                finalUrl = finalUrl.replaceAll(`{${field}}`, value);
            }
        }

        // Add the query variables.
        if(payload.query_variables && Object.keys(payload.query_variables).length > 0) {
            finalUrl += "?" + new URLSearchParams(payload.query_variables).toString();
        }
    }

    return fetch(finalUrl, fetchOptions)
        .then(response => {
            if(response.status >= 200 && response.status < 300) {

                return response.text()
                    .then(responseText => {
                        let jsonData = undefined;
                        try{
                            jsonData = JSON.parse(responseText);
                        } catch(e){
                        }
                        if(jsonData.error === true){
                            let errorText = '';
                            if(_.isArray(jsonData.errors)){
                                jsonData.errors.forEach(errText => {
                                    errorText += '\n' + errText;
                                });
                            } else {
                                errorText = JSON.stringify(jsonData.errors);
                            }
                            throw Error(errorText);
                        } else if(jsonData.data !== undefined){
                            jsonData = jsonData.data;
                        }
                        return jsonData;
                    });
            } else {
                throw Error(response.statusText);
            }
        });
}