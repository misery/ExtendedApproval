const ActionView = Spina.spina(class extends RB.Actions.ActionView {
    static events = {
        'click': 'waitIt',
    }

    async waitIt(e?: JQuery.ClickEvent) {
        if (e) {
            e.preventDefault();
            e.stopPropagation();
        }

        if (confirm(_`Are you sure you want to ShipIt?`)) {
            const page = RB.PageManager.getPage();
            const pageModel = page.model;

            const pendingReview = pageModel.get('pendingReview')
            await pendingReview.ready();
            pendingReview.set({
                bodyTop: _`Ship It!`,
                shipIt: true,
            });

            const comment = pendingReview.createGeneralComment(undefined, true);
            comment.set({
                text: _`Wait for CI!`,
            });
            await comment.save();

            await pendingReview.publish();
            const reviewRequest = pageModel.get('reviewRequest');
            RB.navigateTo(reviewRequest.get('reviewURL'));
        }

        return false;
    }
});

ExtendedApprovalExtension = {
    ActionView,
}
