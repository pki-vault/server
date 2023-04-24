package validation

import "github.com/go-playground/validator/v10"

func RegisterCustomValidators(validate *validator.Validate) error {
	if err := validate.RegisterValidation("not_empty", notEmpty); err != nil {
		return err
	}
	return nil
}

func notEmpty(fl validator.FieldLevel) bool {
	return len(fl.Field().String()) > 0
}
