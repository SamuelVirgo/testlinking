import * as actions from './actions.js';
import _ from 'lodash';
import { combineReducers } from 'redux';

const initialState = {
    messages: new Map(),
    tasks: new Map()
};

const reducerMain = (state = initialState, action = {}) => {
    const {type, payload} = action;
    if (type === actions.set_field) {
        return Object.assign({}, state, {
            [payload.key]: payload.value,
        });
    } else if (type === actions.change_input) {
        let fieldName = payload.name;
        let value = payload.value;

        // build new object and get field name
        const fields = fieldName.split('.');
        fields.reverse().forEach((field, index) => {
            if (index === fields.length - 1) {
                fieldName = field;
            } else {
                value = {[field]: value};
            }
        });

        const storeObj = {[fieldName]: value};
        if (fieldName !== payload.name) {
            // add original field and value
            storeObj[payload.name] = payload.value;

            // merge old state object with new object
            if (state.hasOwnProperty(fieldName)) {
                storeObj[fieldName] = _.merge(state[fieldName], storeObj[fieldName])
            }
        }

        return Object.assign({}, state, storeObj);
    } else if (type === actions.log_task_started) {
        let status = state.tasks.get(payload);
        if(status){
            status.stage = 'started';
            status.counter += 1;
        } else {
            status = {
                stage: 'started',
                counter: 1
            }
        }
        state = Object.assign({}, state);
        state.tasks.set(payload, status);
        return state;
    } else if (type === actions.log_task_done) {
        let status = state.tasks.get(payload);
        if(status) {
            state = Object.assign({}, state);
            if(status.counter > 1){
                status.counter -= 1;
                state.tasks.set(payload, status);
            } else {
                state.tasks.delete(payload);
            }
        } else {
            console.warn('Some process tried to call DONE action for ' + payload + ' which was not started before.');
        }
        return state;
    } else if(type === actions.log_task_errored || type === actions.log_task_success) {
        state = Object.assign({}, state);
        state.messages.set(payload.timestamp, {
            text: payload.text,
            type: type
        });
        return state;
    } else if(type === actions.log_task_close) {
        state = Object.assign({}, state);
        state.messages.delete(payload);
        return state;
    }
    return state;
}

const reducer = combineReducers({
    reducer: reducerMain,
});

export default reducer;