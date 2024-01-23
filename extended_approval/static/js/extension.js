class ActionView extends RB.ActionView {
    events() {
        return {
            'click': '_onClick',
        }
    }

    _onClick() {
        log.error('hello')
    }
}

ExtendedApprovalExtension = {
    ActionView,
}
